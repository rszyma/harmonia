//! Pull-through fetching from upstream binary caches, with progressive
//! serving.
//!
//! A narinfo miss is proxied from upstream with its `URL:` rewritten to
//! this cache's canonical NAR route. The client's follow-up NAR request
//! starts a single download of the upstream NAR into a temp file;
//! concurrent requests for the same path stream the growing file instead
//! of waiting for a full import. When the download completes, the path
//! is imported into the local store with `nix copy`, preserving the
//! upstream signatures that Nix records. Later requests are served from
//! the store normally. Narinfo-only clients never trigger a download:
//! pulls start exclusively on NAR requests.
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
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
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
/// Carries no narinfo: pulls are spawned by NAR requests, which already
/// know their store hash, and the task re-fetches the narinfo itself.
#[derive(Debug)]
pub(crate) struct ActiveDownload {
    dir: tempfile::TempDir,
    nar_path: PathBuf,
    /// Bumped on every progress event. Unlike `Notify`, a watch version
    /// cannot be missed by a reader that checks the file first and waits
    /// after: any missed bump still counts as newer on the next check.
    progress: watch::Sender<u64>,
    generation: AtomicU64,
    done: AtomicBool,
    failed: AtomicBool,
    /// NAR streams currently attached. Only streaming readers count:
    /// narinfo responses complete immediately and hold nothing.
    readers: AtomicUsize,
    /// Last time a reader attached or detached (creation time, which is
    /// effectively attach time: every pull is born from a NAR request that
    /// immediately streams it).
    /// Together with `readers` this tells the download task whether any
    /// downstream is still interested.
    last_reader_seen: Mutex<Instant>,
}

impl ActiveDownload {
    fn new() -> io::Result<Self> {
        let dir = tempfile::TempDir::new()?;
        let nar_path = dir.path().join("data.nar");
        // Reserve the name up front so readers never observe a missing file.
        std::fs::File::create(&nar_path)?;
        let (progress, _) = watch::channel(0u64);
        Ok(Self {
            dir,
            nar_path,
            progress,
            generation: AtomicU64::new(0),
            done: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            readers: AtomicUsize::new(0),
            last_reader_seen: Mutex::new(Instant::now()),
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

    /// Whether the download must be abandoned: the cancel policy is on,
    /// no reader is attached, and the last detach (or pull birth, which
    /// is effectively attach time) is older than `linger`. Every pull is
    /// born from a NAR request that immediately streams it, so an idle
    /// pull means its readers disconnected. The linger only debounces
    /// genuine disconnects, so a flapping reader does not kill a pull
    /// another client is about to rejoin.
    fn should_cancel(&self, enabled: bool, linger: Duration) -> bool {
        enabled
            && self.readers.load(Ordering::Acquire) == 0
            && self
                .last_reader_seen
                .lock()
                .expect("lock poisoned")
                .elapsed()
                >= linger
    }
}

/// Counts one attached NAR reader for as long as it is held. Dropping the
/// response stream (client disconnect) detaches automatically.
struct ReaderGuard {
    dl: Arc<ActiveDownload>,
}

impl ReaderGuard {
    fn new(dl: &Arc<ActiveDownload>) -> Self {
        dl.readers.fetch_add(1, Ordering::Release);
        Self { dl: dl.clone() }
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.dl.readers.fetch_sub(1, Ordering::Release);
        *self.dl.last_reader_seen.lock().expect("lock poisoned") = Instant::now();
    }
}

/// Reattach window before an unread download is cancelled. Generous next
/// to the millisecond-scale narinfo-to-NAR gap of a normal client.
const READER_LINGER: Duration = Duration::from_secs(10);

type HyperClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<bytes::Bytes>,
>;

/// Global for all upstreams: what a download does when it loses its last
/// downstream reader. `false` (default) keeps the current behavior — the
/// download runs to completion in the background and warms the cache;
/// `true` aborts it, so disconnected clients stop costing upstream
/// traffic. Either way a later request simply starts a fresh download.
/// Recently fetched upstream narinfos: (fetched_at, upstream, text).
/// Lets the pull task reuse the narinfo the serving path already fetched
/// instead of re-fetching per pull, and de-duplicates narinfo herds that
/// arrive within the TTL. Expires by time, not by pull lifecycle, so
/// there is nothing to coordinate or clean up — and no correctness
/// impact when it misses: every user re-fetches. Narinfos are
/// effectively immutable per hash (same store path, hashes and sizes;
/// only the rewritten URL and accumulated sigs vary), so a short TTL's
/// staleness window is harmless.
#[derive(Debug)]
struct CachedNarinfo {
    at: Instant,
    upstream: Url,
    text: String,
}

/// Memo horizon: covers serve-to-pull gaps and herds, not deep queues.
const NARINFO_TTL: Duration = Duration::from_secs(60);
/// Memory bound: past this many entries, new fetches simply are not
/// memoized (degrades to re-fetching, never to wrong serving).
const NARINFO_CACHE_CAP: usize = 10_000;

#[derive(Debug)]
pub(crate) struct PullThrough {
    upstreams: Vec<Url>,
    cancel_on_disconnect: bool,
    client: HyperClient,
    downloads: Mutex<HashMap<String, Arc<ActiveDownload>>>,
    narinfo_cache: Mutex<HashMap<String, CachedNarinfo>>,
}

impl Default for PullThrough {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            cancel_on_disconnect: false,
            client: default_client(),
            downloads: Mutex::new(HashMap::new()),
            narinfo_cache: Mutex::new(HashMap::new()),
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
    pub(crate) fn new(upstreams: Vec<Url>, cancel_on_disconnect: bool) -> Result<Self, String> {
        for upstream in &upstreams {
            if upstream.scheme() != "http" && upstream.scheme() != "https" {
                return Err(format!("upstream_caches: unsupported scheme in {upstream}"));
            }
        }
        let client = default_client();
        Ok(Self {
            upstreams,
            cancel_on_disconnect,
            client,
            downloads: Mutex::new(HashMap::new()),
            narinfo_cache: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        !self.upstreams.is_empty()
    }

    /// Resolve a missing hash: already local, being downloaded, or absent.
    /// Starts at most one download per hash; concurrent requests attach to
    /// it. Spawns without fetching anything: the task re-fetches the
    /// narinfo itself, so the NAR response starts streaming immediately.
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
        let dl = match ActiveDownload::new() {
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
                    tokio::spawn(run_download(task_settings, task_hash, dl.clone()));
                    entry.insert(dl).clone()
                }
                std::collections::hash_map::Entry::Occupied(entry) => entry.get().clone(),
            }
        };
        Download::Streaming(dl)
    }

    /// Memoized narinfo lookup for tests: `ttl` is `NARINFO_TTL` in
    /// production. `upstream` restricts the hit to one source, so
    /// per-upstream failover never reads another upstream's bytes.
    fn cached_narinfo(
        &self,
        hash: &str,
        upstream: Option<&Url>,
        ttl: Duration,
    ) -> Option<(Url, String)> {
        let cache = self.narinfo_cache.lock().expect("lock poisoned");
        let entry = cache.get(hash)?;
        if entry.at.elapsed() >= ttl {
            return None;
        }
        if let Some(upstream) = upstream
            && &entry.upstream != upstream
        {
            return None;
        }
        Some((entry.upstream.clone(), entry.text.clone()))
    }

    fn store_narinfo(&self, hash: &str, upstream: Url, text: String) {
        let mut cache = self.narinfo_cache.lock().expect("lock poisoned");
        cache.retain(|_, entry| entry.at.elapsed() < NARINFO_TTL);
        if cache.len() >= NARINFO_CACHE_CAP {
            // Full under pressure: skip memoizing rather than serving
            // wrong. Degrades to re-fetching, nothing else changes.
            return;
        }
        cache.insert(
            hash.to_string(),
            CachedNarinfo {
                at: Instant::now(),
                upstream,
                text,
            },
        );
    }

    /// Fetch `<hash>.narinfo` from the first upstream that has it.
    pub(crate) async fn fetch_narinfo(&self, hash: &str) -> Option<(Url, String)> {
        if let Some(hit) = self.cached_narinfo(hash, None, NARINFO_TTL) {
            return Some(hit);
        }
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
        if let Some((_, text)) = self.cached_narinfo(hash, Some(upstream), NARINFO_TTL) {
            return Some(text);
        }
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
                Ok(text) => {
                    self.store_narinfo(hash, upstream.clone(), text.clone());
                    Some(text)
                }
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
        let reader = ReaderGuard::new(&dl);
        let file = tokio::fs::File::open(&dl.nar_path).await?;
        let progress = dl.subscribe();
        Ok(unfold(
            ReaderState {
                file,
                sent: 0,
                dl,
                progress,
                failed: false,
                // Held for the stream's lifetime: dropping the stream
                // (client disconnect) detaches the reader.
                _reader: reader,
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
    _reader: ReaderGuard,
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

/// Download the NAR (failing over across upstreams), then import it. The
/// narinfo is resolved inside the task: NAR requests carry only the store
/// hash, and nothing is stored between the narinfo and NAR requests by
/// design. A short-TTL memo usually makes this a cache hit on the fetch
/// the serving path just did, not a second upstream GET.
async fn run_download(settings: web::Data<Config>, hash: String, dl: Arc<ActiveDownload>) {
    let _cleanup = FinishGuard {
        downloads: &settings.pull_through.downloads,
        hash: hash.clone(),
    };
    let pull = &settings.pull_through;
    for upstream in &pull.upstreams {
        if dl.should_cancel(pull.cancel_on_disconnect, READER_LINGER) {
            tracing::info!("pull-through: all readers gone, cancelling download of {hash}");
            dl.mark_failed();
            return;
        }
        let narinfo_text = match pull.fetch_narinfo_from(upstream, &hash).await {
            Some(text) => text,
            None => continue,
        };
        let Some(path) = parse_store_path(&narinfo_text) else {
            tracing::warn!("pull-through: narinfo from {upstream} has no StorePath");
            continue;
        };
        let Some(nar_url) = parse_nar_url(&narinfo_text, upstream) else {
            continue;
        };
        tracing::info!("pull-through: pulling {path} from {upstream}");
        match download_to_file(pull, &nar_url, &dl).await {
            Ok(()) => {
                if dl.should_cancel(pull.cancel_on_disconnect, READER_LINGER) {
                    tracing::info!("pull-through: all readers gone, skipping import of {hash}");
                    dl.mark_failed();
                    return;
                }
                dl.mark_done();
                if import_staged(&settings.store, pull, &dl, &hash, &path, &narinfo_text).await {
                    tracing::info!("pull-through: imported {path}");
                }
                return;
            }
            Err(e) => {
                if dl.should_cancel(pull.cancel_on_disconnect, READER_LINGER) {
                    tracing::info!("pull-through: all readers gone, cancelling pull of {hash}");
                    dl.mark_failed();
                    return;
                }
                tracing::warn!("pull-through: download of {nar_url} failed: {e}");
                continue;
            }
        }
    }
    dl.mark_failed();
}

/// Resolves when the download must be abandoned under the cancel policy.
/// With the policy off it never resolves, so `select!` just waits on the
/// other branch. Polled at 1s granularity: prompt next to the 10s linger
/// without waking the task per chunk.
async fn cancelled(dl: &ActiveDownload, enabled: bool) {
    while !dl.should_cancel(enabled, READER_LINGER) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
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
        // hanging the download (and its readers) forever. The cancel
        // branch also fires while blocked on a slow upstream, so an
        // unread download is abandoned promptly instead of at the next
        // chunk.
        let frame = tokio::select! {
            biased;
            _ = cancelled(dl, pull.cancel_on_disconnect) => {
                return Err(io::Error::other("all readers disconnected"));
            }
            frame = tokio::time::timeout(Duration::from_secs(60), body.frame()) => frame
                .map_err(|_| io::Error::other(format!("upstream {nar_url} stalled")))?,
        };
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
    pull: &PullThrough,
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

    let mut child = match command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            tracing::error!("pull-through: failed to run `nix copy`: {e}");
            return false;
        }
    };
    // Drain stderr concurrently so `nix copy` can never block on a full
    // pipe while polled below.
    let mut stderr = child.stderr.take();
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(ref mut pipe) = stderr {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });
    // Poll for exit so a disconnect during the import kills `nix copy`
    // instead of letting it finish: an interrupted copy never leaves a
    // valid store path, so abandoning it is safe. Readers racing the kill
    // see `failed`.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                tracing::error!("pull-through: failed waiting for `nix copy`: {e}");
                let _ = child.kill().await;
                stderr_task.abort();
                return false;
            }
        }
        if dl.should_cancel(pull.cancel_on_disconnect, READER_LINGER) {
            tracing::info!("pull-through: all readers gone, killing import of {hash}");
            let _ = child.kill().await;
            let _ = child.wait().await;
            stderr_task.abort();
            dl.mark_failed();
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    if !status.success() {
        let stderr: String = String::from_utf8_lossy(&stderr_task.await.unwrap_or_default())
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

/// Rewrite an upstream narinfo's `URL:` to this cache's canonical NAR
/// route, so the client's follow-up request lands on the existing
/// `/nar/<narhash>.nar?hash=` handler — which streams the in-flight pull
/// or serves the store — instead of a filename only the upstream routes.
/// Everything else stays verbatim, so hashes and signatures keep matching
/// the downloaded bytes. `None` when the narinfo names no usable NAR
/// hash (the caller then serves it verbatim; unroutable names 404 and
/// the client falls back, absolute URLs fetch direct as before).
pub(crate) fn canonical_narinfo(narinfo: &str, outhash: &str) -> Option<String> {
    let narhash = narinfo
        .lines()
        .filter_map(|line| line.strip_prefix("NarHash: sha256:"))
        .next()?;
    if narhash.len() != 52
        || !narhash
            .bytes()
            .all(|b| harmonia_utils_base_encoding::base32::ALPHABET.contains(b as char))
    {
        return None;
    }
    let mut out = String::new();
    for line in narinfo.lines() {
        if line.starts_with("URL: ") {
            out.push_str(&format!("URL: nar/{narhash}.nar?hash={outhash}\n"));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    Some(out)
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
    fn rewrites_upstream_url_to_canonical() {
        let narhash = "abcd".repeat(13);
        assert_eq!(narhash.len(), 52);
        let outhash = "0123456789abcdfghijklmnpqrsvwxyz";
        let narinfo = format!(
            "StorePath: /nix/store/abc-widget\n\
             URL: nar/blob.bin\n\
             NarHash: sha256:{narhash}\n\
             NarSize: 1\n"
        );
        assert_eq!(
            canonical_narinfo(&narinfo, outhash).as_deref(),
            Some(
                format!(
                    "StorePath: /nix/store/abc-widget\n\
                 URL: nar/{narhash}.nar?hash={outhash}\n\
                 NarHash: sha256:{narhash}\n\
                 NarSize: 1\n"
                )
                .as_str()
            )
        );
        // Absolute upstream URLs rewrite the same way: the client then
        // pulls through us instead of fetching direct.
        let narinfo = narinfo.replace("URL: nar/blob.bin", "URL: https://s3.example/nar/x.nar");
        assert!(
            canonical_narinfo(&narinfo, outhash)
                .expect("rewritten")
                .contains(&format!("URL: nar/{narhash}.nar?hash=")),
        );
        // No usable NAR hash: leave the narinfo alone (verbatim serves
        // absolute URLs direct; unroutable relatives 404 and fall back).
        assert_eq!(
            canonical_narinfo("StorePath: /nix/store/a-b\n", "abc"),
            None
        );
        assert_eq!(
            canonical_narinfo("URL: nar/x.nar\nNarHash: sha256:short\n", "abc"),
            None
        );
    }

    #[test]
    fn narinfo_memo_hits_and_expires() {
        use std::time::Duration;
        let pull = PullThrough::new(vec![], false).expect("empty upstreams");
        let upstream = Url::parse("http://127.0.0.1:8501").unwrap();
        let other = Url::parse("http://127.0.0.1:8502").unwrap();
        assert!(pull.cached_narinfo("abc", None, Duration::ZERO).is_none());
        pull.store_narinfo("abc", upstream.clone(), "text".to_string());
        // Unrestricted hit while fresh.
        assert_eq!(
            pull.cached_narinfo("abc", None, Duration::from_secs(3600)),
            Some((upstream.clone(), "text".to_string()))
        );
        // Upstream-restricted hit: same source OK, other source is a miss
        // (failover must never read another upstream's bytes).
        assert!(
            pull.cached_narinfo("abc", Some(&upstream), Duration::from_secs(3600))
                .is_some()
        );
        assert!(
            pull.cached_narinfo("abc", Some(&other), Duration::from_secs(3600))
                .is_none()
        );
        assert!(
            pull.cached_narinfo("unknown", None, Duration::from_secs(3600))
                .is_none()
        );
        // Expired entries miss however queried.
        assert!(pull.cached_narinfo("abc", None, Duration::ZERO).is_none());
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

        let dl = Arc::new(ActiveDownload::new().expect("temp dir"));
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
    fn reader_guard_counts_attachment() {
        let dl = Arc::new(ActiveDownload::new().expect("temp dir"));
        assert_eq!(dl.readers.load(Ordering::Acquire), 0);
        let first = ReaderGuard::new(&dl);
        let second = ReaderGuard::new(&dl);
        assert_eq!(dl.readers.load(Ordering::Acquire), 2);
        drop(first);
        assert_eq!(dl.readers.load(Ordering::Acquire), 1);
        drop(second);
        assert_eq!(dl.readers.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cancels_only_after_a_disconnect() {
        use std::time::Duration;
        let dl = Arc::new(ActiveDownload::new().expect("temp dir"));
        // Policy off: never cancels, however idle.
        assert!(!dl.should_cancel(false, Duration::ZERO));
        // An attached reader suppresses cancellation however idle.
        let _reader = ReaderGuard::new(&dl);
        assert!(!dl.should_cancel(true, Duration::ZERO));
        // Detached beyond the linger: cancel.
        drop(_reader);
        assert!(dl.should_cancel(true, Duration::ZERO));
        // ...but not before the linger elapses.
        assert!(!dl.should_cancel(true, Duration::from_secs(3600)));
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
