use crate::config::Config;
use crate::error::{CacheError, IoErrorContext, StoreError};
use crate::pull_through::{Download, PullThrough};
use crate::{cache_control_max_age_1y, some_or_404};
use actix_web::web::Bytes;
use actix_web::{HttpRequest, HttpResponse, http, web};
use harmonia_file_nar::NarByteStream;
use harmonia_store_path::StorePathHash;
use harmonia_utils_hash::Hash;
use harmonia_utils_hash::HashFormat as _;
use serde::Deserialize;

/// Represents the query string of a NAR URL.
#[derive(Debug, Deserialize)]
pub struct NarRequest {
    hash: Option<String>,
}

/// Represents the parsed parts in a NAR URL.
#[derive(Debug, Deserialize)]
pub struct PathParams {
    narhash: String,
    outhash: Option<String>,
}

// TODO(conni2461): still missing
// - handle downloadHash/downloadSize and fileHash/fileSize after implementing compression

// Credit actix_web actix-files: https://github.com/actix/actix-web/blob/master/actix-files/src/range.rs
#[derive(Debug)]
struct HttpRange {
    start: u64,
    length: u64,
}

impl HttpRange {
    /// Parses Range HTTP header string as per RFC 2616.
    ///
    /// `header` is HTTP Range header (e.g. `bytes=bytes=0-9`).
    /// `size` is full size of response (file).
    fn parse(
        header: &str,
        size: u64,
    ) -> std::result::Result<Vec<Self>, http_range::HttpRangeParseError> {
        http_range::HttpRange::parse(header, size).map(|ranges| {
            ranges
                .iter()
                .map(|range| Self {
                    start: range.start,
                    length: range.length,
                })
                .collect()
        })
    }
}

pub(crate) async fn get(
    path: web::Path<PathParams>,
    req: HttpRequest,
    q: web::Query<NarRequest>,
    settings: web::Data<Config>,
) -> crate::ServerResult {
    // Extract the narhash from the query parameter, and bail out if it's missing or invalid.
    let narhash = some_or_404!(Some(path.narhash.as_str()));

    // lookup the store path.
    // We usually extract the outhash from the query parameter.
    // However, when processing nix-serve URLs, it's present in the path
    // directly.
    let outhash = if let Some(outhash) = &q.hash {
        Some(outhash.as_str())
    } else {
        path.outhash.as_deref()
    };
    let outhash = match outhash {
        Some(outhash) => outhash,
        None => {
            return Ok(HttpResponse::NotFound()
                .insert_header(crate::cache_control_no_store())
                .body("missing outhash"));
        }
    };
    // Validate hash shape so garbage input becomes a 4xx, not a db scan.
    let store_path_hash = StorePathHash::decode_digest(outhash.as_bytes()).map_err(|e| {
        CacheError::from(StoreError::PathQuery {
            hash: outhash.to_string(),
            reason: format!("Invalid hash format: {e}"),
        })
    })?;

    // Single SQLite lookup yields both the store path and its nar hash/size.
    let info = match settings
        .store
        .query_path_info_by_hash_part(&store_path_hash)?
    {
        Some(info) => info,
        None => match PullThrough::get_or_start(&settings, outhash).await {
            Download::Absent => {
                return Ok(HttpResponse::NotFound()
                    .insert_header(crate::cache_control_no_store())
                    .body("store path not found"));
            }
            // The import may have finished concurrently; re-check.
            Download::Present => match settings
                .store
                .query_path_info_by_hash_part(&store_path_hash)?
            {
                Some(info) => info,
                None => {
                    return Ok(HttpResponse::NotFound()
                        .insert_header(crate::cache_control_no_store())
                        .body("store path not found"));
                }
            },
            Download::Streaming(dl) => {
                match settings
                    .store
                    .query_path_info_by_hash_part(&store_path_hash)?
                {
                    Some(info) => info,
                    None => {
                        // The download is still running: stream the
                        // growing file. No Content-Length (unknown yet)
                        // and no ranges on in-progress downloads.
                        let stream = PullThrough::stream_nar(dl)
                            .await
                            .io_context("failed opening the in-progress download")?;
                        return Ok(HttpResponse::Ok()
                            .insert_header((
                                http::header::CONTENT_TYPE,
                                crate::zstd_body::NAR_CONTENT_TYPE,
                            ))
                            .streaming(stream));
                    }
                }
            }
        },
    };
    let store_path = &info.path;

    let nar_hash: Hash = info.info.nar_hash.into();
    let nar_size = info.info.nar_size;
    let expected_hash = nar_hash.as_base32().as_bare().to_string();
    if narhash != expected_hash {
        return Ok(HttpResponse::NotFound()
            .insert_header(crate::cache_control_no_store())
            .body("hash mismatch detected"));
    }

    let rlength = nar_size;
    let mut res = HttpResponse::Ok();

    let real_path = settings.store.get_real_path(store_path);

    // Credit actix_web actix-files: https://github.com/actix/actix-web/blob/master/actix-files/src/named.rs#L525
    if let Some(ranges) = req.headers().get(http::header::RANGE) {
        if let Ok(ranges_header) = ranges.to_str() {
            if let Ok(ranges) = HttpRange::parse(ranges_header, rlength)
                && let Some(first) = ranges.first()
            {
                let range_length = first.length;
                let offset = first.start;

                res.insert_header((
                    http::header::CONTENT_RANGE,
                    format!(
                        "bytes {}-{}/{}",
                        offset,
                        offset + range_length - 1,
                        nar_size
                    ),
                ));

                // For range requests, we need to skip bytes and limit output
                let stream = NarByteStream::new(real_path);
                let ranged_stream = create_range_stream(stream, offset, range_length);

                return Ok(res
                    .status(http::StatusCode::PARTIAL_CONTENT)
                    .insert_header((
                        http::header::CONTENT_TYPE,
                        crate::zstd_body::NAR_CONTENT_TYPE,
                    ))
                    .insert_header((http::header::ACCEPT_RANGES, "bytes"))
                    .insert_header(cache_control_max_age_1y())
                    .body(actix_web::body::SizedStream::new(
                        range_length,
                        ranged_stream,
                    )));
            } else {
                res.insert_header((http::header::CONTENT_RANGE, format!("bytes */{rlength}")));
                return Ok(res.status(http::StatusCode::RANGE_NOT_SATISFIABLE).finish());
            };
        } else {
            return Ok(res.status(http::StatusCode::BAD_REQUEST).finish());
        };
    }

    // Non-range request: stream the full NAR
    let stream = NarByteStream::new(real_path);

    Ok(res
        .insert_header((
            http::header::CONTENT_TYPE,
            crate::zstd_body::NAR_CONTENT_TYPE,
        ))
        .insert_header((http::header::ACCEPT_RANGES, "bytes"))
        .insert_header(cache_control_max_age_1y())
        // Sized so the zstd middleware can pledge the exact length.
        .body(actix_web::body::SizedStream::new(rlength, stream)))
}

/// Serve an in-flight pull-through download by the upstream file name.
/// Upstream narinfos are served verbatim, so their `URL:` may name files
/// outside harmonia's own `/nar/<hash>.nar` routes (e.g. c.n.o's
/// `nar/<file>.nar.zst`). This catch-all (registered after the specific
/// routes, so it only sees paths they reject) streams the growing file
/// for a path no other route matched, as long as its pull is still
/// running. Anything else stays 404 and the client falls back to its next
/// substituter — including the narrow race where the pull finished between
/// the client's narinfo and NAR requests.
///
/// Streaming the temp file (rather than the store) is required for
/// correctness here, not just convenience: the client verifies the bytes
/// against the verbatim narinfo (`FileHash`/`NarHash`), and only the
/// downloaded bytes match those. Absolute upstream URLs never reach this
/// handler — the client fetches those straight from the upstream.
pub(crate) async fn get_inflight(
    tail: web::Path<String>,
    settings: web::Data<Config>,
) -> crate::ServerResult {
    let candidate = format!("/nar/{}", tail.into_inner());
    let dl = match PullThrough::find_by_nar_path(&settings.pull_through, &candidate) {
        Some(dl) => dl,
        None => {
            return Ok(HttpResponse::NotFound()
                .insert_header(crate::cache_control_no_store())
                .body("store path not found"));
        }
    };
    let stream = PullThrough::stream_nar(dl)
        .await
        .io_context("failed opening the in-progress download")?;
    Ok(HttpResponse::Ok()
        .insert_header((
            http::header::CONTENT_TYPE,
            crate::zstd_body::NAR_CONTENT_TYPE,
        ))
        .streaming(stream))
}

/// Create a stream that skips `offset` bytes and returns at most `length` bytes.
fn create_range_stream<S>(
    stream: S,
    offset: u64,
    length: u64,
) -> impl futures_core::Stream<Item = std::result::Result<Bytes, std::io::Error>>
where
    S: futures_core::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Unpin,
{
    futures_util::stream::unfold(
        (stream, offset, length, 0u64),
        |(mut stream, offset, length, mut sent)| async move {
            use futures_util::StreamExt;

            loop {
                match stream.next().await {
                    Some(Ok(data)) => {
                        let data_len = data.len() as u64;

                        // If we haven't reached the offset yet
                        if sent + data_len <= offset {
                            sent += data_len;
                            continue;
                        }

                        // Calculate the slice we need from this chunk
                        let start = if sent < offset {
                            (offset - sent) as usize
                        } else {
                            0
                        };

                        let remaining = length - (sent.saturating_sub(offset).min(length));
                        if remaining == 0 {
                            return None;
                        }

                        let end = (start as u64 + remaining).min(data_len) as usize;

                        sent += data_len;

                        if start < end {
                            let slice = data.slice(start..end);
                            return Some((Ok(slice), (stream, offset, length, sent)));
                        }
                    }
                    Some(Err(e)) => return Some((Err(e), (stream, offset, length, sent))),
                    None => return None,
                }
            }
        },
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::{IoErrorContext, Result};
    use futures_util::StreamExt;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    async fn dump_to_vec(path: PathBuf) -> Vec<u8> {
        let stream = NarByteStream::new(path);
        futures_util::pin_mut!(stream);

        let mut result = Vec::new();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.expect("Stream error during NAR dump");
            result.extend_from_slice(&bytes);
        }
        result
    }

    #[tokio::test]
    async fn test_dump_store() -> Result<()> {
        let temp_dir =
            harmonia_utils_test::CanonicalTempDir::new().expect("Failed to create temp dir");
        let dir = temp_dir.path().to_path_buf();
        fs::write(dir.join("file"), b"somecontent").io_context("Failed to write test file")?;

        fs::create_dir(dir.join("some_empty_dir")).io_context("Failed to create test empty dir")?;

        let some_dir = dir.join("some_dir");
        fs::create_dir(&some_dir).io_context("Failed to create test dir")?;

        let executable_path = some_dir.join("executable");
        fs::write(&executable_path, b"somescript").io_context("Failed to write test executable")?;
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o755))
            .io_context("Failed to set test executable permissions")?;

        std::os::unix::fs::symlink("sometarget", dir.join("symlink"))
            .io_context("Failed to create test symlink")?;

        let nar_dump = dump_to_vec(dir.clone()).await;
        let res = Command::new("nix-store")
            .arg("--dump")
            .arg(dir)
            .output()
            .expect("Failed to run nix-store --dump");
        assert_eq!(res.status.code(), Some(0));
        println!("nar_dump len: {}", nar_dump.len());
        println!("nix-store --dump len: {}", res.stdout.len());
        // println!("nix-store --dump:");
        assert_eq!(res.stdout, nar_dump);

        Ok(())
    }
}
