//! One in-flight pull: download into a temp file, stream to clients, import.
//!
//! The temp file is the buffer between the download and its readers. The
//! download writes at upstream speed, and every reader follows at its own
//! pace, so a slow client never holds back the download or other clients.
//! Hot data stays in the page cache, and memory use does not depend on how
//! far behind a reader is.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::web;
use bytes::Bytes;
use futures_core::Stream;
use harmonia_store_remote::{DaemonClient, DaemonStore as _};
use harmonia_utils_hash::{Algorithm, Context, Hash};
use tempfile::TempPath;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

use super::{Resolved, upstream};
use crate::config::Config;

/// Grace period between the last reader leaving and a cancellation.
const READER_LINGER: Duration = Duration::from_secs(10);
/// Longest wait for the next upstream bytes before the download fails.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CHUNK_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    /// A client asked for the NAR.
    Request,
    /// The import of another path needs this path as a reference.
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Downloading,
    /// The whole NAR is in the temp file and matches its hash.
    Downloaded,
    Imported,
    ImportFailed,
    DownloadFailed,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct State {
    /// Verified-length prefix of the temp file that readers may send.
    written: u64,
    pub(super) phase: Phase,
}

pub(crate) struct Pull {
    pub(super) resolved: Arc<Resolved>,
    origin: Origin,
    /// Deleted when the last reader and the task are done with the pull.
    file: TempPath,
    state: watch::Sender<State>,
    readers: AtomicUsize,
    last_detach: Mutex<Instant>,
    /// Never cancelled: an import depends on this path.
    pinned: AtomicBool,
}

impl Pull {
    pub(super) fn new(resolved: Arc<Resolved>, origin: Origin) -> io::Result<Self> {
        let file = tempfile::Builder::new()
            .prefix("harmonia-pull-")
            .tempfile()?
            .into_temp_path();
        Ok(Self {
            resolved,
            origin,
            file,
            state: watch::Sender::new(State {
                written: 0,
                phase: Phase::Downloading,
            }),
            readers: AtomicUsize::new(0),
            last_detach: Mutex::new(Instant::now()),
            pinned: AtomicBool::new(origin == Origin::Dependency),
        })
    }

    pub(super) fn pin(&self) {
        self.pinned.store(true, Ordering::Release);
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<State> {
        self.state.subscribe()
    }

    fn set_phase(&self, phase: Phase) {
        self.state.send_modify(|s| s.phase = phase);
    }

    /// Whether the cancel policy applies now. Before the first reader
    /// attaches, the creation time counts as the last detach.
    fn should_cancel(&self, policy: bool) -> bool {
        policy
            && !self.pinned.load(Ordering::Acquire)
            && self.readers.load(Ordering::Acquire) == 0
            && self.last_detach.lock().expect("lock poisoned").elapsed() >= READER_LINGER
    }

    /// Stream the NAR from the start. The stream follows the download and
    /// ends with an error if the download fails.
    pub(crate) async fn stream(
        self: &Arc<Self>,
    ) -> io::Result<impl Stream<Item = io::Result<Bytes>> + use<>> {
        let reader = Reader::attach(self);
        let file = tokio::fs::File::open(&self.file).await?;
        let state = self.subscribe();
        let nar_size = self.resolved.nar_size();
        Ok(futures_util::stream::unfold(
            (reader, file, state, 0u64, false),
            move |(reader, mut file, mut state, mut sent, done)| async move {
                if done {
                    return None;
                }
                loop {
                    let current = *state.borrow_and_update();
                    // Hold back the last byte until the hash is verified, so
                    // no client ever receives a complete, corrupt response.
                    let verified = matches!(
                        current.phase,
                        Phase::Downloaded | Phase::Imported | Phase::ImportFailed
                    );
                    let available = if verified {
                        current.written
                    } else {
                        current.written.min(nar_size.saturating_sub(1))
                    };
                    if sent < available {
                        let len = (available - sent).min(CHUNK_SIZE as u64) as usize;
                        let mut buf = vec![0; len];
                        let item = file.read_exact(&mut buf).await.map(|_| Bytes::from(buf));
                        let failed = item.is_err();
                        sent += len as u64;
                        return Some((item, (reader, file, state, sent, failed)));
                    }
                    match current.phase {
                        Phase::Downloading => {
                            if state.changed().await.is_err() {
                                let e = io::Error::other("pull state dropped");
                                return Some((Err(e), (reader, file, state, sent, true)));
                            }
                        }
                        Phase::DownloadFailed => {
                            let e = io::Error::other("upstream download failed");
                            return Some((Err(e), (reader, file, state, sent, true)));
                        }
                        Phase::Downloaded | Phase::Imported | Phase::ImportFailed => return None,
                    }
                }
            },
        ))
    }
}

/// Counts an attached reader while held.
struct Reader(Arc<Pull>);

impl Reader {
    fn attach(pull: &Arc<Pull>) -> Self {
        pull.readers.fetch_add(1, Ordering::AcqRel);
        Self(pull.clone())
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        *self.0.last_detach.lock().expect("lock poisoned") = Instant::now();
        self.0.readers.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Removes the pull from the registry when the task ends, on every path.
struct Registered<'a>(&'a web::Data<Config>, &'a Arc<Pull>);

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.0.pull_through.unregister(self.1);
        // A task that dies early must not leave readers waiting.
        self.1.state.send_if_modified(|s| {
            let unfinished = matches!(s.phase, Phase::Downloading | Phase::Downloaded);
            if unfinished {
                s.phase = match s.phase {
                    Phase::Downloading => Phase::DownloadFailed,
                    _ => Phase::ImportFailed,
                };
            }
            unfinished
        });
    }
}

/// Task body of a pull: download, then import.
pub(super) async fn run(settings: web::Data<Config>, pull: Arc<Pull>) {
    let _registered = Registered(&settings, &pull);
    let pt = &settings.pull_through;
    let resolved = &pull.resolved;
    let path = &resolved.narinfo.path;

    let downloaded = {
        // Requested pulls have a client waiting; only background pulls of
        // references queue for a slot.
        let _permit = match pull.origin {
            Origin::Dependency => Some(pt.dependency_downloads.acquire().await),
            Origin::Request => None,
        };
        tracing::info!("pull-through: pulling {path} from {}", resolved.upstream);
        download(&pull, pt).await
    };
    if let Err(e) = downloaded {
        tracing::warn!("pull-through: download of {path} failed: {e}");
        pull.set_phase(Phase::DownloadFailed);
        return;
    }
    pull.set_phase(Phase::Downloaded);

    match import(&settings, &pull).await {
        Ok(()) => {
            tracing::info!("pull-through: imported {path}");
            pull.set_phase(Phase::Imported);
        }
        Err(e) => {
            tracing::warn!("pull-through: import of {path} failed: {e}");
            pull.set_phase(Phase::ImportFailed);
        }
    }
}

/// Resolves when the cancel policy fires. Never resolves with the policy off.
async fn cancelled(pull: &Pull, policy: bool) {
    if !policy {
        return std::future::pending().await;
    }
    while !pull.should_cancel(policy) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Download, decompress and verify the NAR into the temp file.
async fn download(pull: &Pull, pt: &super::PullThrough) -> io::Result<()> {
    let info = &pull.resolved.narinfo.info.info;
    let nar_size = info.nar_size;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&pull.file)
        .await?;
    file.seek(io::SeekFrom::Start(0)).await?;

    let download = async {
        let mut nar = upstream::open_nar(&pt.tls, &pull.resolved).await?;
        let mut hasher = Context::new(Algorithm::SHA256);
        let mut buf = vec![0; CHUNK_SIZE];
        let mut written = 0u64;
        loop {
            let n = tokio::time::timeout(IDLE_TIMEOUT, nar.read(&mut buf))
                .await
                .map_err(|_| io::Error::other("upstream stalled"))??;
            if n == 0 {
                break;
            }
            // Also bounds what a bogus compressed stream can expand to.
            if written + n as u64 > nar_size {
                return Err(io::Error::other(format!("NAR exceeds NarSize {nar_size}")));
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).await?;
            // tokio completes file writes in the background; flush so the
            // bytes are in the file before readers are told about them.
            file.flush().await?;
            written += n as u64;
            pull.state.send_modify(|s| s.written = written);
        }
        if written != nar_size {
            return Err(io::Error::other(format!(
                "NAR is {written} bytes, NarSize is {nar_size}"
            )));
        }
        if hasher.finish() != Hash::from(info.nar_hash) {
            return Err(io::Error::other("NAR does not match NarHash"));
        }
        Ok(())
    };

    tokio::select! {
        biased;
        () = cancelled(pull, pt.cancel_on_disconnect) => {
            Err(io::Error::other("all clients disconnected"))
        }
        result = download => result,
    }
}

/// Add the downloaded NAR to the local store through the Nix daemon.
async fn import(settings: &web::Data<Config>, pull: &Pull) -> Result<(), String> {
    let pt = &settings.pull_through;
    let store = &settings.store;
    let info = pull.resolved.path_info();

    // The daemon rejects paths with invalid references, so complete the
    // closure first. A client usually substituted the references just
    // before, so they are valid or in flight.
    let references = info
        .info
        .references
        .iter()
        .filter(|r| **r != info.path && !store.is_valid_path(r).unwrap_or(false));
    let results =
        futures_util::future::join_all(references.map(|r| pt.ensure_present(settings, r))).await;
    for result in results {
        result.map_err(|e| format!("reference: {e}"))?;
    }

    let mut daemon = DaemonClient::builder()
        .set_store_dir(store.store_dir())
        .connect_unix(&pt.daemon_socket)
        .await
        .map_err(|e| format!("connecting to {}: {e}", pt.daemon_socket.display()))?;
    let nar = tokio::fs::File::open(&pull.file)
        .await
        .map_err(|e| e.to_string())?;
    let nar = tokio::io::BufReader::with_capacity(CHUNK_SIZE, nar);
    // Signatures are checked: an untrusted daemon client cannot skip that.
    daemon
        .add_to_store_nar(&info, nar, false, false)
        .await
        .map_err(|e| e.to_string())
}
