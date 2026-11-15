//! HTTP access to upstream binary caches.

use std::cell::OnceCell;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt as _;
use harmonia_store_nar_info::parse_narinfo_txt;
use harmonia_store_path::{StoreDir, StorePathHash};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufRead, AsyncRead};
use tokio_util::io::StreamReader;
use url::Url;

use super::Resolved;

/// Upper bound for a narinfo body. Real ones are well below 64 KiB even with
/// thousands of references.
const MAX_NARINFO_SIZE: usize = 1024 * 1024;
/// Time allowed to connect and receive the response head.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// NAR compression methods that pull-through can decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compression {
    None,
    Xz,
    Zstd,
    Bzip2,
}

impl Compression {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "xz" => Some(Self::Xz),
            "zstd" => Some(Self::Zstd),
            "bzip2" => Some(Self::Bzip2),
            _ => None,
        }
    }
}

thread_local! {
    // awc clients are bound to the worker thread (actix runtime), so every
    // worker gets its own client and connection pool.
    static CLIENT: OnceCell<awc::Client> = const { OnceCell::new() };
}

fn client(tls: &Arc<ClientConfig>) -> awc::Client {
    CLIENT.with(|client| {
        client
            .get_or_init(|| {
                awc::Client::builder()
                    .connector(awc::Connector::new().rustls_0_23(tls.clone()))
                    .timeout(REQUEST_TIMEOUT)
                    .add_default_header((
                        awc::http::header::USER_AGENT,
                        concat!("harmonia/", env!("CARGO_PKG_VERSION")),
                    ))
                    .finish()
            })
            .clone()
    })
}

/// TLS settings for upstream connections. With `native_roots`, trust the
/// CA certificates of the system store (`SSL_CERT_FILE`/`SSL_CERT_DIR`
/// override its location). An error if that finds no certificate.
pub(super) fn tls_config(native_roots: bool) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    if native_roots {
        let found = rustls_native_certs::load_native_certs();
        for e in &found.errors {
            tracing::warn!("pull-through: loading CA certificates: {e}");
        }
        let (added, ignored) = roots.add_parsable_certificates(found.certs);
        if added == 0 {
            return Err(
                "upstream_caches: no CA certificates found in the system store \
                 (set SSL_CERT_FILE to a CA bundle)"
                    .to_string(),
            );
        }
        tracing::debug!("pull-through: trusting {added} CA certificates ({ignored} unparsable)");
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Fetch and validate `<hash>.narinfo` from `upstream`. `Ok(None)` if the
/// upstream does not have the path.
pub(super) async fn fetch_narinfo(
    tls: &Arc<ClientConfig>,
    upstream: &Url,
    store_dir: &StoreDir,
    hash: &StorePathHash,
) -> Result<Option<Resolved>, String> {
    let url = upstream
        .join(&format!("{hash}.narinfo"))
        .map_err(|e| e.to_string())?;
    let mut response = client(tls)
        .get(url.as_str())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    match response.status().as_u16() {
        200 => {}
        // S3-style buckets answer 403 for missing keys.
        403 | 404 | 410 => return Ok(None),
        status => return Err(format!("HTTP {status}")),
    }
    let body = response
        .body()
        .limit(MAX_NARINFO_SIZE)
        .await
        .map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(&body).map_err(|e| e.to_string())?;
    // Also rejects a store dir other than ours: such paths cannot be
    // imported under the same name.
    let narinfo = parse_narinfo_txt(store_dir, text).map_err(|e| e.to_string())?;
    if narinfo.path.hash() != hash {
        return Err(format!("narinfo describes {}", narinfo.path));
    }
    let compression = narinfo.info.compression.as_deref().unwrap_or("bzip2");
    let compression = Compression::parse(compression)
        .ok_or_else(|| format!("unsupported compression {compression:?}"))?;
    let nar_url = narinfo.info.url.as_deref().ok_or("narinfo has no URL")?;
    let nar_url = upstream.join(nar_url).map_err(|e| e.to_string())?;
    if nar_url.scheme() != "http" && nar_url.scheme() != "https" {
        return Err(format!("unsupported NAR URL {nar_url}"));
    }
    Ok(Some(Resolved {
        upstream: upstream.clone(),
        narinfo,
        nar_url,
        compression,
    }))
}

/// Open the NAR of `resolved` as an uncompressed byte stream.
pub(super) async fn open_nar(
    tls: &Arc<ClientConfig>,
    resolved: &Resolved,
) -> io::Result<Pin<Box<dyn AsyncRead>>> {
    use async_compression::tokio::bufread::{BzDecoder, XzDecoder, ZstdDecoder};

    let response = client(tls)
        .get(resolved.nar_url.as_str())
        .send()
        .await
        .map_err(|e| io::Error::other(format!("{}: {e}", resolved.nar_url)))?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "{}: HTTP {}",
            resolved.nar_url,
            response.status()
        )));
    }
    let body: Pin<Box<dyn AsyncBufRead>> =
        Box::pin(StreamReader::new(response.map_err(io::Error::other)));
    Ok(match resolved.compression {
        Compression::None => body,
        Compression::Xz => {
            let mut decoder = XzDecoder::new(body);
            decoder.multiple_members(true);
            Box::pin(decoder)
        }
        Compression::Zstd => {
            let mut decoder = ZstdDecoder::new(body);
            decoder.multiple_members(true);
            Box::pin(decoder)
        }
        Compression::Bzip2 => {
            let mut decoder = BzDecoder::new(body);
            decoder.multiple_members(true);
            Box::pin(decoder)
        }
    })
}
