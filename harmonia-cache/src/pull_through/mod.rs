//! Pull-through from upstream binary caches into the local Nix store.
//!
//! When a requested path is missing locally, harmonia resolves its narinfo
//! from the configured upstreams and answers as if the path were local:
//!
//! - A narinfo request returns the upstream path info rendered in
//!   harmonia's own format (`Compression: none`, harmonia's NAR URL). It
//!   carries only the upstream signatures. Nothing is downloaded.
//! - A NAR request starts one download per path (later requests for the
//!   same path join it). The download decompresses the upstream NAR,
//!   checks it against `NarHash`/`NarSize` and appends it to a temp file.
//!   Every client streams that file while it grows, at its own pace.
//! - A completed download is imported through the Nix daemon
//!   (`AddToStoreNar`) from the temp file, so each NAR crosses the network
//!   once. The daemon checks the upstream signatures. References missing
//!   locally are pulled first through the same mechanism, because the
//!   store only accepts paths whose references are valid.
//!
//! Cold and warm responses are byte-identical apart from signatures, so a
//! client that cached a narinfo during the pull can use it after the
//! import, too.

mod pull;
mod upstream;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::{HttpResponse, http, web};
use harmonia_store_nar_info::NarInfo;
use harmonia_store_path::{StoreDir, StorePath, StorePathHash};
use harmonia_store_path_info::ValidPathInfo;
use tokio::sync::Semaphore;
use url::Url;

use crate::config::Config;
pub(crate) use pull::Pull;
use pull::{Origin, Phase};
pub(crate) use upstream::Compression;

/// How long a resolved (or confirmed missing) narinfo is reused. Covers the
/// gap between the narinfo and the NAR request of one substitution, and the
/// reference walk of an import.
const NARINFO_TTL: Duration = Duration::from_secs(60);
/// Bound on remembered narinfos. When full, new results are not memoized.
const NARINFO_MEMO_CAP: usize = 10_000;
/// Concurrent downloads of references that no client asked for.
const DEPENDENCY_DOWNLOADS: usize = 8;

/// An upstream narinfo that passed validation.
#[derive(Debug)]
pub(crate) struct Resolved {
    pub(crate) upstream: Url,
    pub(crate) narinfo: NarInfo,
    pub(crate) nar_url: Url,
    pub(crate) compression: Compression,
}

impl Resolved {
    pub(crate) fn path_info(&self) -> ValidPathInfo {
        ValidPathInfo {
            path: self.narinfo.path.clone(),
            info: self.narinfo.info.info.clone(),
        }
    }

    fn nar_size(&self) -> u64 {
        self.narinfo.info.info.nar_size
    }
}

struct Memo {
    at: Instant,
    resolved: Option<Arc<Resolved>>,
}

pub(crate) struct PullThrough {
    upstreams: Vec<Url>,
    cancel_on_disconnect: bool,
    daemon_socket: PathBuf,
    tls: Arc<rustls::ClientConfig>,
    /// In-flight pulls by store path hash. An entry lives from the first NAR
    /// request until its import ends.
    pulls: Mutex<HashMap<StorePathHash, Arc<Pull>>>,
    narinfos: Mutex<HashMap<StorePathHash, Memo>>,
    dependency_downloads: Semaphore,
}

impl Default for PullThrough {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            cancel_on_disconnect: false,
            daemon_socket: PathBuf::new(),
            tls: upstream::tls_config(false).expect("TLS config without roots"),
            pulls: Mutex::new(HashMap::new()),
            narinfos: Mutex::new(HashMap::new()),
            dependency_downloads: Semaphore::new(DEPENDENCY_DOWNLOADS),
        }
    }
}

impl PullThrough {
    pub(crate) fn new(
        upstreams: &[Url],
        cancel_on_disconnect: bool,
        daemon_socket: PathBuf,
    ) -> Result<Self, String> {
        let upstreams = upstreams
            .iter()
            .map(|url| {
                if url.scheme() != "http" && url.scheme() != "https" {
                    return Err(format!(
                        "upstream_caches: {url}: only http and https are supported"
                    ));
                }
                // Make relative joins keep the last path segment.
                let mut url = url.clone();
                if !url.path().ends_with('/') {
                    url.set_path(&format!("{}/", url.path()));
                }
                Ok(url)
            })
            .collect::<Result<Vec<Url>, _>>()?;
        let tls = upstream::tls_config(upstreams.iter().any(|u| u.scheme() == "https"))?;
        Ok(Self {
            upstreams,
            tls,
            cancel_on_disconnect,
            daemon_socket,
            ..Self::default()
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        !self.upstreams.is_empty()
    }

    /// Look up `hash` in the upstreams, in order. `None` if no upstream has
    /// a usable narinfo for it.
    pub(crate) async fn resolve(
        &self,
        store_dir: &StoreDir,
        hash: &StorePathHash,
    ) -> Option<Arc<Resolved>> {
        if let Some(memo) = self.narinfos.lock().expect("lock poisoned").get(hash)
            && memo.at.elapsed() < NARINFO_TTL
        {
            return memo.resolved.clone();
        }
        let mut resolved = None;
        let mut clean_miss = true;
        for upstream in &self.upstreams {
            match upstream::fetch_narinfo(&self.tls, upstream, store_dir, hash).await {
                Ok(Some(found)) => {
                    resolved = Some(Arc::new(found));
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("pull-through: {upstream}: narinfo for {hash}: {e}");
                    clean_miss = false;
                }
            }
        }
        // Do not remember a miss that may be a transient upstream error.
        if resolved.is_some() || clean_miss {
            let mut memo = self.narinfos.lock().expect("lock poisoned");
            memo.retain(|_, m| m.at.elapsed() < NARINFO_TTL);
            if memo.len() < NARINFO_MEMO_CAP {
                memo.insert(
                    *hash,
                    Memo {
                        at: Instant::now(),
                        resolved: resolved.clone(),
                    },
                );
            }
        }
        resolved
    }

    /// Join the in-flight pull of `resolved`, or start one. `None` if the
    /// path became valid locally in the meantime.
    fn start_or_join(
        &self,
        settings: &web::Data<Config>,
        resolved: Arc<Resolved>,
        origin: Origin,
    ) -> std::io::Result<Option<Arc<Pull>>> {
        let hash = *resolved.narinfo.path.hash();
        let mut pulls = self.pulls.lock().expect("lock poisoned");
        if let Some(pull) = pulls.get(&hash) {
            if origin == Origin::Dependency {
                pull.pin();
            }
            return Ok(Some(pull.clone()));
        }
        // Checked under the lock: a pull leaves the map only after its
        // import ended, so either the entry or the valid path is visible.
        if settings
            .store
            .is_valid_path(&resolved.narinfo.path)
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let pull = Arc::new(Pull::new(resolved, origin)?);
        pulls.insert(hash, pull.clone());
        actix_web::rt::spawn(pull::run(settings.clone(), pull.clone()));
        Ok(Some(pull))
    }

    /// Make `path` valid in the local store, pulling it if needed.
    async fn ensure_present(
        &self,
        settings: &web::Data<Config>,
        path: &StorePath,
    ) -> Result<(), String> {
        let store = &settings.store;
        // One retry: a joined pull can fail for a reason that a fresh one
        // does not hit (e.g. it was cancelled before it got pinned).
        for _ in 0..2 {
            if store.is_valid_path(path).unwrap_or(false) {
                return Ok(());
            }
            let resolved = self
                .resolve(store.store_dir(), path.hash())
                .await
                .ok_or_else(|| format!("{path} is not in any upstream"))?;
            if resolved.narinfo.path != *path {
                return Err(format!("upstream narinfo for {path} names another path"));
            }
            let Some(pull) = self
                .start_or_join(settings, resolved, Origin::Dependency)
                .map_err(|e| format!("creating a temp file for {path}: {e}"))?
            else {
                continue;
            };
            pull.finished().await;
        }
        if store.is_valid_path(path).unwrap_or(false) {
            Ok(())
        } else {
            Err(format!("could not pull {path}"))
        }
    }

    fn unregister(&self, pull: &Arc<Pull>) {
        let mut pulls = self.pulls.lock().expect("lock poisoned");
        let hash = pull.resolved.narinfo.path.hash();
        if pulls.get(hash).is_some_and(|p| Arc::ptr_eq(p, pull)) {
            pulls.remove(hash);
        }
    }
}

/// Outcome of a NAR request that missed the local store.
pub(crate) enum NarMiss {
    Response(HttpResponse),
    /// The path became valid locally while resolving; serve it normally.
    NowLocal,
}

/// Answer a NAR request for a path that is not in the local store.
pub(crate) async fn serve_nar(
    settings: &web::Data<Config>,
    hash: &StorePathHash,
    narhash: &str,
) -> NarMiss {
    use harmonia_utils_hash::{Hash, HashFormat as _};

    let pt = &settings.pull_through;
    let not_found = |msg: &'static str| {
        NarMiss::Response(
            HttpResponse::NotFound()
                .insert_header(crate::cache_control_no_store())
                .body(msg),
        )
    };
    let Some(resolved) = pt.resolve(settings.store.store_dir(), hash).await else {
        return not_found("store path not found");
    };
    let nar_hash: Hash = resolved.narinfo.info.info.nar_hash.into();
    if nar_hash.as_base32().as_bare().to_string() != narhash {
        return not_found("hash mismatch detected");
    }
    let pull = match pt.start_or_join(settings, resolved.clone(), Origin::Request) {
        Ok(Some(pull)) => pull,
        Ok(None) => return NarMiss::NowLocal,
        Err(e) => {
            tracing::error!("pull-through: creating a temp file: {e}");
            return not_found("store path not found");
        }
    };
    let stream = match pull.stream().await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::error!("pull-through: opening the download of {hash}: {e}");
            return not_found("store path not found");
        }
    };
    // No `Accept-Ranges`: the file is still growing.
    NarMiss::Response(
        HttpResponse::Ok()
            .insert_header((
                http::header::CONTENT_TYPE,
                crate::zstd_body::NAR_CONTENT_TYPE,
            ))
            .insert_header(crate::cache_control_max_age_1y())
            .body(actix_web::body::SizedStream::new(
                resolved.nar_size(),
                stream,
            )),
    )
}

/// Path info for a narinfo request that missed the local store. The caller
/// renders it like a local path, but must not sign it: the content is not
/// verified until the NAR is downloaded.
pub(crate) async fn narinfo(
    settings: &web::Data<Config>,
    hash: &StorePathHash,
) -> Option<ValidPathInfo> {
    let resolved = settings
        .pull_through
        .resolve(settings.store.store_dir(), hash)
        .await?;
    tracing::debug!(
        "pull-through: narinfo for {} from {}",
        resolved.narinfo.path,
        resolved.upstream
    );
    Some(resolved.path_info())
}

impl Pull {
    /// Wait until the pull ended, whatever the outcome.
    async fn finished(&self) {
        let mut state = self.subscribe();
        let _ = state
            .wait_for(|s| !matches!(s.phase, Phase::Downloading | Phase::Downloaded))
            .await;
    }
}
