//! Pull-through fetching from upstream binary caches, with progressive
//! serving.
//!
//! The first request for a missing path starts a single download of the
//! upstream NAR into a temp file; concurrent requests for the same path
//! stream the growing file instead of waiting for a full import. When the
//! download completes, the path is imported into the local store with
//! `nix copy`, preserving the upstream signatures that Nix records. Later
//! requests are served from the store normally.
//!
//! Why a temp file and not an in-memory pool: downloader, client readers and
//! importer are fully decoupled and never block each other. The downloader
//! writes at line speed with no backpressure; readers poll the growing file
//! independently; the importer runs on completion. The temp file *is* the
//! buffer, and the kernel page cache keeps hot bytes in RAM automatically: no
//! size knobs, no upload/download race detection, no memory explosion (a slow
//! client only slows its own stream), no premature disk spill (spill is the
//! design, at zero cost while pages stay cached). Extra disk use is one NAR
//! per concurrent cold path, cleaned up with the download state.
//!
//! Security: verification stays end to end. Clients re-verify the streamed
//! NAR against the served narinfo (hashes plus signatures); the only write
//! path into the local store is `nix copy`, which independently re-verifies
//! hashes and signatures. A failed download aborts readers (clients fall back
//! to their next substituter) and never registers anything locally.

use crate::config::Config;
use crate::store::Store;
use actix_web::web;
use futures_util::stream::unfold;
use harmonia_store_path::{StorePath, StorePathHash};
use http_body_util::BodyExt as _;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;
use url::Url;

/// What a miss resolved to.
pub(crate) enum Download {
    /// Already in the local store; serve it normally.
    Present,
    /// Being fetched; stream it progressively.
    Streaming(Arc<ActiveDownload>),
    /// No upstream has it (or pull-through disabled).
    Absent,
}

/// One in-flight upstream download. The temp dir (NAR file plus import
/// staging) is deleted when the last reference — readers included — drops.
#[derive(Debug)]
pub(crate) struct ActiveDownload {
    dir: tempfile::TempDir,
    nar_path: PathBuf,
    /// Upstream narinfo bytes, served verbatim until the import lands.
    pub(crate) narinfo: String,
    /// Bumped on every progress event. Unlike `Notify`, a watch version
    /// cannot be missed by a reader that checks the file first and waits
    /// after: any missed bump still counts as newer on the next check.
    progress: watch::Sender<u64>,
    generation: AtomicU64,
    done: AtomicBool,
    failed: AtomicBool,
}

impl ActiveDownload {
    fn new(narinfo: String) -> io::Result<Self> {
        let dir = tempfile::TempDir::new()?;
        let nar_path = dir.path().join("data.nar");
        // Reserve the name up front so readers never observe a missing file.
        std::fs::File::create(&nar_path)?;
        let (progress, _) = watch::channel(0u64);
        Ok(Self {
            dir,
            nar_path,
            narinfo,
            progress,
            generation: AtomicU64::new(0),
            done: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        })
    }

    /// Subscribe to progress events. Never misses an event: any bump after
    /// the returned receiver is created resolves a pending wait.
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.progress.subscribe()
    }

    fn bump(&self) {
        let generation = self
            .generation
            .fetch_add(1, Ordering::Release)
            .wrapping_add(1);
        let _ = self.progress.send(generation);
    }

    fn mark_done(&self) {
        self.done.store(true, Ordering::Release);
        self.bump();
    }

    fn mark_failed(&self) {
        self.failed.store(true, Ordering::Release);
        self.bump();
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
}

type HyperClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<bytes::Bytes>,
>;

#[derive(Debug)]
pub(crate) struct PullThrough {
    upstreams: Vec<Url>,
    client: HyperClient,
    downloads: Mutex<HashMap<String, Arc<ActiveDownload>>>,
}

impl Default for PullThrough {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            client: default_client(),
            downloads: Mutex::new(HashMap::new()),
        }
    }
}

fn default_client() -> HyperClient {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider)
        .expect("static webpki roots are valid")
        .https_or_http()
        .enable_http1()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}

impl PullThrough {
    pub(crate) fn new(upstreams: Vec<Url>) -> Result<Self, String> {
        for upstream in &upstreams {
            if upstream.scheme() != "http" && upstream.scheme() != "https" {
                return Err(format!("upstream_caches: unsupported scheme in {upstream}"));
            }
        }
        let client = default_client();
        Ok(Self {
            upstreams,
            client,
            downloads: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        !self.upstreams.is_empty()
    }

    /// Resolve a missing hash: already local, being downloaded, or absent.
    /// Starts at most one download per hash; concurrent requests attach to it.
    pub(crate) async fn get_or_start(settings: &web::Data<Config>, hash: &str) -> Download {
        let pull = &settings.pull_through;
        if !pull.enabled() {
            return Download::Absent;
        }
        let decoded = match StorePathHash::decode_digest(hash.as_bytes()) {
            Ok(decoded) => decoded,
            Err(e) => {
                tracing::warn!("pull-through: invalid hash {hash:?}: {e}");
                return Download::Absent;
            }
        };
        if matches!(
            settings.store.query_path_from_hash_part(&decoded),
            Ok(Some(_))
        ) {
            return Download::Present;
        }
        if let Some(dl) = pull.downloads.lock().expect("lock poisoned").get(hash) {
            return Download::Streaming(dl.clone());
        }
        let Some((upstream, narinfo_text)) = pull.fetch_narinfo(hash).await else {
            return Download::Absent;
        };
        let Some(path) = parse_store_path(&narinfo_text) else {
            tracing::warn!("pull-through: narinfo from {upstream} has no StorePath");
            return Download::Absent;
        };
        let dl = match ActiveDownload::new(narinfo_text.clone()) {
            Ok(dl) => Arc::new(dl),
            Err(e) => {
                tracing::warn!("pull-through: failed creating temp file: {e}");
                return Download::Absent;
            }
        };
        let dl = {
            let mut downloads = pull.downloads.lock().expect("lock poisoned");
            match downloads.entry(hash.to_string()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let task_settings = settings.clone();
                    let task_hash = hash.to_string();
                    tokio::spawn(run_download(
                        task_settings,
                        task_hash,
                        dl.clone(),
                        path,
                        (upstream, narinfo_text),
                    ));
                    entry.insert(dl).clone()
                }
                std::collections::hash_map::Entry::Occupied(entry) => {
                    // A racing request inserted first; use the winner. Note
                    // `path`, `upstream` and `narinfo_text` then go unused:
                    // all racing requests name the same store path.
                    entry.get().clone()
                }
            }
        };
        Download::Streaming(dl)
    }

    /// Fetch `<hash>.narinfo` from the first upstream that has it.
    async fn fetch_narinfo(&self, hash: &str) -> Option<(Url, String)> {
        for upstream in &self.upstreams {
            if let Some(text) = self.fetch_narinfo_from(upstream, hash).await {
                return Some((upstream.clone(), text));
            }
        }
        None
    }

    /// GET with redirect following (up to 10 hops; GET is safe to repeat).
    /// Each hop gets its own 30s budget. Only http(s) targets are followed.
    async fn request(&self, url: &str) -> io::Result<hyper::Response<hyper::body::Incoming>> {
        let mut url = url.to_string();
        for _ in 0..10 {
            let uri: hyper::Uri = url
                .parse()
                .map_err(|e| io::Error::other(format!("invalid URL {url}: {e}")))?;
            let req = hyper::Request::builder()
                .uri(uri)
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .map_err(io::Error::other)?;
            let resp = tokio::time::timeout(Duration::from_secs(30), self.client.request(req))
                .await
                .map_err(|_| io::Error::other(format!("request to {url} timed out")))?
                .map_err(|e| io::Error::other(e.to_string()))?;
            if matches!(resp.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                let location = resp
                    .headers()
                    .get(hyper::header::LOCATION)
                    .ok_or_else(|| io::Error::other("redirect without Location"))?
                    .to_str()
                    .map_err(|e| io::Error::other(format!("bad redirect target: {e}")))?;
                let next = Url::parse(&url)
                    .map_err(|e| io::Error::other(format!("bad URL {url}: {e}")))?
                    .join(location)
                    .map_err(|e| {
                        io::Error::other(format!("bad redirect target {location}: {e}"))
                    })?;
                if next.scheme() != "http" && next.scheme() != "https" {
                    return Err(io::Error::other(format!(
                        "refusing to follow redirect to {next}"
                    )));
                }
                url = next.to_string();
                continue;
            }
            return Ok(resp);
        }
        Err(io::Error::other("too many redirects"))
    }

    async fn fetch_narinfo_from(&self, upstream: &Url, hash: &str) -> Option<String> {
        let url = format!("{}/{hash}.narinfo", upstream.as_str().trim_end_matches('/'));
        let resp = match self.request(&url).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!("pull-through: failed fetching narinfo from {url}: {e}");
                return None;
            }
        };
        if !resp.status().is_success() {
            tracing::debug!("pull-through: {url} answered {}", resp.status());
            return None;
        }
        match resp.into_body().collect().await {
            Ok(collected) => match String::from_utf8(collected.to_bytes().to_vec()) {
                Ok(text) => Some(text),
                Err(e) => {
                    tracing::warn!("pull-through: narinfo from {url} is not UTF-8: {e}");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("pull-through: failed reading narinfo from {url}: {e}");
                None
            }
        }
    }

    /// Stream the growing NAR file. Readers never block the download; a slow
    /// reader only slows its own stream. Ends at completion, errors if the
    /// download fails.
    pub(crate) async fn stream_nar(
        dl: Arc<ActiveDownload>,
    ) -> io::Result<impl futures_core::Stream<Item = Result<bytes::Bytes, io::Error>> + Send> {
        let file = tokio::fs::File::open(&dl.nar_path).await?;
        let progress = dl.subscribe();
        Ok(unfold(
            ReaderState {
                file,
                sent: 0,
                dl,
                progress,
                failed: false,
            },
            |mut st| async move {
                if st.failed {
                    return None;
                }
                loop {
                    let len = match st.file.metadata().await {
                        Ok(meta) => meta.len(),
                        Err(e) => {
                            st.failed = true;
                            return Some((Err(e), st));
                        }
                    };
                    // saturating_sub: a failover restarts the file from
                    // zero; readers then observe a short file until it
                    // regrows, and a stale offset can never underflow.
                    let avail = len.saturating_sub(st.sent);
                    if avail > 0 {
                        let n = std::cmp::min(65536, avail) as usize;
                        let mut buf = vec![0u8; n];
                        match st.file.read_exact(&mut buf).await {
                            Ok(_) => {
                                st.sent += n as u64;
                                return Some((Ok(bytes::Bytes::from(buf)), st));
                            }
                            Err(e) => {
                                st.failed = true;
                                return Some((Err(e), st));
                            }
                        }
                    }
                    if st.dl.is_done() {
                        return None;
                    }
                    if st.dl.is_failed() {
                        st.failed = true;
                        return Some((Err(io::Error::other("upstream download failed")), st));
                    }
                    // `changed()` resolves immediately if a bump landed
                    // after this receiver last saw the version, so no
                    // wakeup can be lost between the checks above and here.
                    if st.progress.changed().await.is_err() {
                        // Sender dropped: the download state is gone.
                        st.failed = true;
                        return Some((Err(io::Error::other("upstream download aborted")), st));
                    }
                }
            },
        ))
    }
}

struct ReaderState {
    file: tokio::fs::File,
    sent: u64,
    dl: Arc<ActiveDownload>,
    progress: watch::Receiver<u64>,
    failed: bool,
}

/// Remove the map entry when the download task ends, on every exit path.
/// Readers holding an `Arc` keep the temp dir alive regardless.
struct FinishGuard<'a> {
    downloads: &'a Mutex<HashMap<String, Arc<ActiveDownload>>>,
    hash: String,
}

impl Drop for FinishGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut downloads) = self.downloads.lock() {
            downloads.remove(&self.hash);
        }
    }
}

/// Download the NAR (failing over across upstreams), then import it.
async fn run_download(
    settings: web::Data<Config>,
    hash: String,
    dl: Arc<ActiveDownload>,
    path: StorePath,
    primary: (Url, String),
) {
    let _cleanup = FinishGuard {
        downloads: &settings.pull_through.downloads,
        hash: hash.clone(),
    };
    let pull = &settings.pull_through;
    for upstream in &pull.upstreams {
        let narinfo_text = if *upstream == primary.0 {
            primary.1.clone()
        } else {
            match pull.fetch_narinfo_from(upstream, &hash).await {
                Some(text) => text,
                None => continue,
            }
        };
        let Some(nar_url) = parse_nar_url(&narinfo_text, upstream) else {
            continue;
        };
        match download_to_file(pull, &nar_url, &dl).await {
            Ok(()) => {
                dl.mark_done();
                import_staged(&settings.store, &dl, &hash, &path, &narinfo_text).await;
                return;
            }
            Err(e) => {
                tracing::warn!("pull-through: download of {nar_url} failed: {e}");
                continue;
            }
        }
    }
    dl.mark_failed();
}

/// Fetch one NAR straight into the temp file, notifying readers per chunk.
async fn download_to_file(
    pull: &PullThrough,
    nar_url: &str,
    dl: &ActiveDownload,
) -> io::Result<()> {
    let response = pull.request(nar_url).await?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!("HTTP {}", response.status())));
    }
    let mut body = response.into_body();
    let mut file = tokio::fs::File::create(&dl.nar_path).await?;
    loop {
        // Idle timeout per chunk: a stalled upstream aborts instead of
        // hanging the download (and its readers) forever.
        let frame = tokio::time::timeout(Duration::from_secs(60), body.frame())
            .await
            .map_err(|_| io::Error::other(format!("upstream {nar_url} stalled")))?;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(io::Error::other)?;
        let data = frame
            .into_data()
            .map_err(|_| io::Error::other("unexpected trailers"))?;
        if !data.is_empty() {
            file.write_all(&data).await?;
            dl.bump();
        }
    }
    file.flush().await?;
    Ok(())
}

/// Import the downloaded NAR into the local store with `nix copy --from
/// file://`, which re-verifies hashes and records the upstream signatures.
/// Staging layout mirrors a binary cache; the NAR is hardlinked, not copied.
async fn import_staged(
    store: &Store,
    dl: &ActiveDownload,
    hash: &str,
    path: &StorePath,
    narinfo_text: &str,
) -> bool {
    let cache_dir = dl.dir.path().join("cache");
    let nar_dir = cache_dir.join("nar");
    if std::fs::create_dir_all(&nar_dir).is_err()
        || std::fs::hard_link(&dl.nar_path, nar_dir.join("data.nar")).is_err()
    {
        tracing::warn!("pull-through: failed staging the download");
        return false;
    }
    let staged = match staged_narinfo(narinfo_text, store, path) {
        Some(staged) => staged,
        None => return false,
    };
    if std::fs::write(cache_dir.join(format!("{hash}.narinfo")), staged).is_err()
        || std::fs::write(
            cache_dir.join("nix-cache-info"),
            format!(
                "StoreDir: {}\nWantMassQuery: 1\nPriority: 30\n",
                store.store_dir().to_str()
            ),
        )
        .is_err()
    {
        tracing::warn!("pull-through: failed writing the staging cache");
        return false;
    }
    let mut from = match Url::parse(&format!("file://{}", cache_dir.display())) {
        Ok(from) => from,
        Err(e) => {
            tracing::warn!("pull-through: invalid staging URL: {e}");
            return false;
        }
    };
    from.query_pairs_mut()
        .append_pair("store", store.store_dir().to_str());
    let path_str = format!("{}/{}", store.store_dir().to_str(), path);
    let target = match copy_target(store) {
        Some(target) => target,
        None => {
            tracing::error!(
                "pull-through: cannot derive the import target store; set nix_db_path to the store's db.sqlite"
            );
            return false;
        }
    };
    let mut command = tokio::process::Command::new("nix");
    command.arg("copy").arg("--from").arg(from.as_str());
    if let CopyTarget::Direct(url) = &target {
        command.arg("--to").arg(url);
    }
    command.arg(&path_str);

    let output = match command.output().await {
        Ok(output) => output,
        Err(e) => {
            tracing::error!("pull-through: failed to run `nix copy`: {e}");
            return false;
        }
    };
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        tracing::warn!("pull-through: `nix copy {path_str}` failed: {stderr}");
        return false;
    }
    match store.query_path_from_hash_part(
        &StorePathHash::decode_digest(hash.as_bytes()).expect("hash validated by caller"),
    ) {
        Ok(Some(_)) => true,
        Ok(None) => {
            tracing::warn!(
                "pull-through: `nix copy {path_str}` succeeded but the path is still missing"
            );
            false
        }
        Err(e) => {
            tracing::warn!("pull-through: failed re-reading the store: {e}");
            false
        }
    }
}

/// Extract the store path from a narinfo body. Only the base name
/// (`<hash>-<name>`) is used; the import itself still requires the upstream
/// to serve our store directory (Nix refuses cross-store-dir copies).
fn parse_store_path(narinfo: &str) -> Option<StorePath> {
    narinfo
        .lines()
        .filter_map(|line| line.strip_prefix("StorePath: "))
        .next()
        .and_then(|value| value.rsplit('/').next())
        .and_then(|base| StorePath::from_base_path(base).ok())
}

/// Resolve the narinfo's `URL:` field against the upstream base URL.
fn parse_nar_url(narinfo: &str, upstream: &Url) -> Option<String> {
    let url = narinfo
        .lines()
        .filter_map(|line| line.strip_prefix("URL: "))
        .next()?;
    if url.starts_with("http://") || url.starts_with("https://") {
        return Some(url.to_string());
    }
    Some(format!(
        "{}/{}",
        upstream.as_str().trim_end_matches('/'),
        url.trim_start_matches('/')
    ))
}

/// Build the narinfo for the staging cache: same bytes, same signatures, but
/// pointing at our store dir and our staged NAR file. Missing FileHash (and
/// friends) default to the Nar values, like Nix does.
fn staged_narinfo(narinfo: &str, store: &Store, path: &StorePath) -> Option<String> {
    let mut out = String::new();
    let mut seen_url = false;
    let mut seen_filehash = false;
    let mut seen_filesize = false;
    let mut nar_hash = None;
    let mut nar_size = None;
    for line in narinfo.lines() {
        if line.starts_with("StorePath: ") {
            out.push_str(&format!(
                "StorePath: {}/{path}\n",
                store.store_dir().to_str()
            ));
        } else if line.starts_with("URL: ") {
            out.push_str("URL: nar/data.nar\n");
            seen_url = true;
        } else {
            if line.starts_with("FileHash: ") {
                seen_filehash = true;
            } else if line.starts_with("FileSize: ") {
                seen_filesize = true;
            } else if let Some(value) = line.strip_prefix("NarHash: ") {
                nar_hash = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("NarSize: ") {
                nar_size = Some(value.to_string());
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    if !seen_url {
        out.push_str("URL: nar/data.nar\n");
    }
    if !seen_filehash {
        out.push_str(&format!("FileHash: {}\n", nar_hash?));
    }
    if !seen_filesize {
        out.push_str(&format!("FileSize: {}\n", nar_size?));
    }
    Some(out)
}

/// Where `nix copy` writes the import: the default `/nix/store` goes through
/// the Nix daemon (no `--to` flag), anything else is addressed directly so
/// chroot and test stores work. `None` when the target cannot be derived.
enum CopyTarget {
    /// Import via the Nix daemon into the default store.
    Daemon,
    /// Import into the store at this URL.
    Direct(String),
}

fn copy_target(store: &Store) -> Option<CopyTarget> {
    if store.real_store() == Path::new("/nix/store") {
        return Some(CopyTarget::Daemon);
    }
    let state = store.db_path().parent()?.parent()?;
    Some(CopyTarget::Direct(format!(
        "local?store={}&state={}",
        store.real_store().display(),
        state.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_store_path_with_matching_store_dir() {
        let narinfo = "StorePath: /nix/store/0123456789abcdfghijklmnpqrsvwxyz-widget\n\
             URL: nar/xyz.nar\n\
             NarHash: sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             NarSize: 1\n";
        let path = parse_store_path(narinfo).expect("should parse");
        assert_eq!(path.to_string(), "0123456789abcdfghijklmnpqrsvwxyz-widget");
    }

    #[test]
    fn parses_store_path_with_foreign_store_dir() {
        let narinfo = "StorePath: /tmp/other-store/0123456789abcdfghijklmnpqrsvwxyz-widget\n";
        let path = parse_store_path(narinfo).expect("should parse");
        assert_eq!(path.to_string(), "0123456789abcdfghijklmnpqrsvwxyz-widget");
    }

    #[test]
    fn rejects_narinfo_without_store_path() {
        assert!(parse_store_path("URL: nar/xyz.nar\n").is_none());
        assert!(parse_store_path("").is_none());
    }

    #[test]
    fn resolves_relative_nar_url_against_upstream() {
        let upstream = Url::parse("http://127.0.0.1:8501").unwrap();
        assert_eq!(
            parse_nar_url("URL: nar/xyz.nar\n", &upstream).as_deref(),
            Some("http://127.0.0.1:8501/nar/xyz.nar")
        );
    }

    #[tokio::test]
    async fn streams_growing_file_before_completion() {
        use futures_util::StreamExt as _;
        use tokio::io::AsyncWriteExt as _;

        let dl = Arc::new(
            ActiveDownload::new(
                "StorePath: /nix/store/0123456789abcdfghijklmnpqrsvwxyz-widget\n".to_string(),
            )
            .expect("temp dir"),
        );
        // Feed the file in two chunks with a delay: the reader must see
        // the first chunk before the download is marked done.
        let writer = dl.clone();
        tokio::spawn(async move {
            let mut file = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&writer.nar_path)
                .await
                .expect("open temp file");
            file.write_all(b"first-").await.expect("write");
            writer.bump();
            tokio::time::sleep(Duration::from_millis(500)).await;
            file.write_all(b"second").await.expect("write");
            file.flush().await.expect("flush");
            writer.mark_done();
        });

        let stream = PullThrough::stream_nar(dl).await.expect("open stream");
        tokio::pin!(stream);
        let first = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("first chunk in time")
            .expect("stream not ended")
            .expect("no error");
        assert_eq!(&first[..], b"first-");
        let mut rest = Vec::new();
        while let Some(chunk) = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("chunk in time")
        {
            rest.extend_from_slice(&chunk.expect("no error"));
        }
        assert_eq!(rest, b"second");
    }

    #[test]
    fn keeps_absolute_nar_url() {
        let upstream = Url::parse("http://127.0.0.1:8501").unwrap();
        assert_eq!(
            parse_nar_url("URL: https://s3.example/nar/xyz.nar\n", &upstream).as_deref(),
            Some("https://s3.example/nar/xyz.nar")
        );
    }
}
