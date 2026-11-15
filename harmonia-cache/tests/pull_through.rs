//! Pull-through against a synthetic upstream cache.
//!
//! The upstream is a minimal HTTP server that serves hand-made, signed
//! narinfos and NARs, so the tests control compression, references, timing
//! and corruption, and can count exactly how often each file was fetched.
//! The pull-through cache imports into its own store through a real
//! `nix-daemon`.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    CanonicalTempDir, LocalStore, Result, pick_unused_port, start_harmonia_cache_with_env,
};
use harmonia_store_path::{StoreDir, StorePath};
use harmonia_store_path_info::{NarHash, fingerprint_path};
use harmonia_utils_hash::{Hash, HashFormat as _};
use harmonia_utils_signature::SecretKey;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;

const SECRET_KEY: &str = include_str!("../../tests/cache.sk");
const PUBLIC_KEY: &str = include_str!("../../tests/cache.pk");
const UNTRUSTED_SECRET_KEY: &str = include_str!("../../tests/cache2.sk");

#[derive(Default)]
struct Counters {
    /// Requests per URL path.
    requests: HashMap<String, usize>,
    /// Responses sent to the end, per URL path.
    completed: HashMap<String, usize>,
    /// Responses whose client hung up mid-body, per URL path.
    aborted: HashMap<String, usize>,
}

/// A static HTTP/1.1 upstream. Every response closes its connection.
struct Upstream {
    port: u16,
    tls: bool,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    counters: Arc<Mutex<Counters>>,
}

type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

impl Upstream {
    /// Serve with `delay` between 16 KiB chunks of every body.
    async fn start(delay: Duration) -> Result<Self> {
        Self::start_with(delay, None).await
    }

    /// Serve HTTPS when `tls` is set.
    async fn start_with(delay: Duration, tls: Option<TlsAcceptor>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let files: Files = Arc::default();
        let counters: Arc<Mutex<Counters>> = Arc::default();
        let upstream = Self {
            port,
            tls: tls.is_some(),
            files: files.clone(),
            counters: counters.clone(),
        };
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (files, counters, tls) = (files.clone(), counters.clone(), tls.clone());
                tokio::spawn(async move {
                    match tls {
                        None => serve(socket, files, counters, delay).await,
                        Some(tls) => {
                            if let Ok(socket) = tls.accept(socket).await {
                                serve(socket, files, counters, delay).await;
                            }
                        }
                    }
                });
            }
        });
        Ok(upstream)
    }

    fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://127.0.0.1:{}", self.port)
    }

    fn requests(&self, path: &str) -> usize {
        let counters = self.counters.lock().unwrap();
        counters.requests.get(path).copied().unwrap_or(0)
    }

    fn completed(&self, path: &str) -> usize {
        let counters = self.counters.lock().unwrap();
        counters.completed.get(path).copied().unwrap_or(0)
    }

    fn aborted(&self, path: &str) -> usize {
        let counters = self.counters.lock().unwrap();
        counters.aborted.get(path).copied().unwrap_or(0)
    }

    /// Publish a store path holding one regular file with `contents`.
    async fn publish(&self, store_dir: &StoreDir, path: &Published) -> Result<()> {
        let nar = nar_of_file(&path.contents);
        let (compressed, ext) = compress(&nar, path.compression).await?;
        let store_path = StorePath::from_bytes(path.base.as_bytes())?;
        let references = path
            .references
            .iter()
            .map(|r| StorePath::from_bytes(r.as_bytes()))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let nar_hash = NarHash::digest(&nar);
        let key: SecretKey = path.key.trim().parse()?;
        let sig = key.sign(fingerprint_path(
            store_dir,
            &store_path,
            &nar_hash,
            nar.len() as u64,
            &references,
        ));
        // A corrupt upstream: advertise the hash of other contents.
        let advertised = if path.corrupt {
            NarHash::digest(b"something else")
        } else {
            nar_hash
        };
        let nar_url = format!("nar/{}.nar{ext}", path.hash());
        let mut narinfo = format!(
            "StorePath: {}\nURL: {nar_url}\nCompression: {}\nNarHash: {}\nNarSize: {}\n",
            store_dir.display(&store_path),
            path.compression,
            Hash::from(advertised).as_base32(),
            nar.len(),
        );
        if !path.references.is_empty() {
            narinfo.push_str(&format!("References: {}\n", path.references.join(" ")));
        }
        narinfo.push_str(&format!("Sig: {sig}\n"));
        let mut files = self.files.lock().unwrap();
        files.insert(format!("/{}.narinfo", path.hash()), narinfo.into_bytes());
        files.insert(format!("/{nar_url}"), compressed);
        Ok(())
    }
}

/// Answer one request on `socket`.
async fn serve(
    mut socket: impl AsyncRead + AsyncWrite + Unpin,
    files: Files,
    counters: Arc<Mutex<Counters>>,
    delay: Duration,
) {
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match socket.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    let request = String::from_utf8_lossy(&request);
    let target = request.split(' ').nth(1).unwrap_or("/");
    let path = target.split('?').next().unwrap_or(target).to_string();
    *counters
        .lock()
        .unwrap()
        .requests
        .entry(path.clone())
        .or_default() += 1;
    let body = files.lock().unwrap().get(&path).cloned();
    let Some(body) = body else {
        let _ = socket
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = socket.shutdown().await;
        return;
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if socket.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    for chunk in body.chunks(16 * 1024) {
        if !delay.is_zero() {
            sleep(delay).await;
        }
        // Flush per chunk: TLS streams buffer, and a hang-up must be noticed.
        if socket.write_all(chunk).await.is_err() || socket.flush().await.is_err() {
            *counters.lock().unwrap().aborted.entry(path).or_default() += 1;
            return;
        }
    }
    let _ = socket.shutdown().await;
    *counters.lock().unwrap().completed.entry(path).or_default() += 1;
}

/// A fresh CA and a certificate for 127.0.0.1 that it signed.
struct TestPki {
    ca_pem: String,
    acceptor: TlsAcceptor,
}

impl TestPki {
    fn new() -> Result<Self> {
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        use rustls_pki_types::PrivatePkcs8KeyDer;
        use tokio_rustls::rustls;

        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;
        let key = KeyPair::generate()?;
        let cert = CertificateParams::new(vec!["127.0.0.1".to_string()])?.signed_by(&key, &ca)?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
        Ok(Self {
            ca_pem: ca.pem(),
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }
}

struct Published {
    base: String,
    contents: Vec<u8>,
    references: Vec<String>,
    compression: &'static str,
    key: &'static str,
    corrupt: bool,
}

impl Published {
    fn new(n: u32, name: &str, contents: impl Into<Vec<u8>>) -> Self {
        Self {
            base: format!("{n:032}-{name}"),
            contents: contents.into(),
            references: Vec::new(),
            compression: "xz",
            key: SECRET_KEY,
            corrupt: false,
        }
    }

    fn hash(&self) -> &str {
        &self.base[..32]
    }

    fn nar_path(&self) -> String {
        let ext = match self.compression {
            "xz" => ".xz",
            "zstd" => ".zst",
            "bzip2" => ".bz2",
            _ => "",
        };
        format!("/nar/{}.nar{ext}", self.hash())
    }
}

/// NAR serialisation of a single regular file.
fn nar_of_file(contents: &[u8]) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s);
        out.resize(out.len().next_multiple_of(8), 0);
    }
    let mut out = Vec::new();
    for token in [
        &b"nix-archive-1"[..],
        b"(",
        b"type",
        b"regular",
        b"contents",
    ] {
        put(&mut out, token);
    }
    put(&mut out, contents);
    put(&mut out, b")");
    out
}

async fn compress(nar: &[u8], compression: &str) -> Result<(Vec<u8>, &'static str)> {
    use async_compression::tokio::write::{BzEncoder, XzEncoder};
    Ok(match compression {
        "none" => (nar.to_vec(), ""),
        "xz" => {
            let mut encoder = XzEncoder::new(Vec::new());
            encoder.write_all(nar).await?;
            encoder.shutdown().await?;
            (encoder.into_inner(), ".xz")
        }
        "bzip2" => {
            let mut encoder = BzEncoder::new(Vec::new());
            encoder.write_all(nar).await?;
            encoder.shutdown().await?;
            (encoder.into_inner(), ".bz2")
        }
        "zstd" => (zstd::encode_all(nar, 3)?, ".zst"),
        other => return Err(format!("unknown compression {other}").into()),
    })
}

/// The pull-through cache under test, with its own store and daemon.
struct PullThroughCache {
    _root: CanonicalTempDir,
    store: LocalStore,
    store_dir: StoreDir,
    port: u16,
    _daemon: Child,
    _cache: Box<dyn Send>,
}

impl PullThroughCache {
    async fn start(upstream: &Upstream, cancel_on_disconnect: bool) -> Result<Self> {
        Self::start_with(&[upstream], cancel_on_disconnect, &[]).await
    }

    async fn start_with(
        upstreams: &[&Upstream],
        cancel_on_disconnect: bool,
        env: &[(&str, &Path)],
    ) -> Result<Self> {
        let root = CanonicalTempDir::new()?;
        let store = LocalStore::init(root.path())?;
        let store_dir = StoreDir::new(store.store_dir.clone())?;
        let daemon_socket = root.path().join("daemon.sock");
        let daemon = spawn_daemon(root.path(), &store, &daemon_socket).await?;
        let port = pick_unused_port().ok_or("no free port")?;
        let config = format!(
            r#"
bind = "127.0.0.1:{port}"
virtual_nix_store = "{store_dir}"
nix_db_path = "{db}"
upstream_caches = [{upstreams}]
upstream_cancel_on_disconnect = {cancel_on_disconnect}
nix_daemon_socket = "{socket}"
"#,
            store_dir = store.store_dir.display(),
            db = store.db_path().display(),
            upstreams = upstreams
                .iter()
                .map(|u| format!("\"{}\"", u.url()))
                .collect::<Vec<_>>()
                .join(", "),
            socket = daemon_socket.display(),
        );
        let cache = start_harmonia_cache_with_env(&config, port, env).await?;
        Ok(Self {
            _root: root,
            store,
            store_dir,
            port,
            _daemon: daemon,
            _cache: cache,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn store_url(&self) -> String {
        format!(
            "local?store={}&state={}",
            self.store.store_dir.display(),
            self.store.state_dir.display()
        )
    }

    fn full_path(&self, path: &Published) -> String {
        format!("{}/{}", self.store.store_dir.display(), path.base)
    }

    async fn is_valid(&self, path: &Published) -> Result<bool> {
        let status = Command::new("nix-store")
            .args(["--store", &self.store_url(), "--check-validity"])
            .arg(self.full_path(path))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        Ok(status.success())
    }

    async fn wait_valid(&self, path: &Published) -> Result<()> {
        timeout(Duration::from_secs(60), async {
            while !self.is_valid(path).await? {
                sleep(Duration::from_millis(100)).await;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
        .map_err(|_| format!("{} was never imported", path.base))?
    }

    async fn signatures(&self, path: &Published) -> Result<String> {
        let output = Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "path-info",
                "--sigs",
                "--store",
                &self.store_url(),
            ])
            .arg(self.full_path(path))
            .output()
            .await?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }

    async fn narinfo(&self, path: &Published) -> Result<String> {
        let body = curl(&self.url(&format!("/{}.narinfo", path.hash()))).await?;
        Ok(String::from_utf8(body)?)
    }

    /// The NAR request a Nix client makes after reading `narinfo`.
    async fn nar_for(&self, narinfo: &str) -> Result<Vec<u8>> {
        curl(&self.url(&format!("/{}", nar_url(narinfo)?))).await
    }
}

async fn spawn_daemon(root: &Path, store: &LocalStore, socket: &Path) -> Result<Child> {
    let conf_dir = root.join("etc");
    let log_dir = root.join("log");
    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::write(
        conf_dir.join("nix.conf"),
        format!(
            "trusted-public-keys = {}\nrequire-sigs = true\nbuild-users-group =\n",
            PUBLIC_KEY.trim()
        ),
    )?;
    let child = Command::new("nix-daemon")
        .env("NIX_STORE_DIR", &store.store_dir)
        .env("NIX_STATE_DIR", &store.state_dir)
        .env("NIX_LOG_DIR", &log_dir)
        .env("NIX_CONF_DIR", &conf_dir)
        .env("NIX_DAEMON_SOCKET_PATH", socket)
        .env_remove("NIX_REMOTE")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    timeout(Duration::from_secs(30), async {
        while !socket.exists() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "nix-daemon did not create its socket")?;
    Ok(child)
}

fn nar_url(narinfo: &str) -> Result<String> {
    Ok(narinfo
        .lines()
        .find_map(|l| l.strip_prefix("URL: "))
        .ok_or("narinfo has no URL")?
        .to_string())
}

fn curl_command(url: &str) -> Command {
    let mut command = Command::new("curl");
    command.args(["-sSf", "--max-time", "60", url]);
    command
}

async fn curl(url: &str) -> Result<Vec<u8>> {
    let output = curl_command(url).output().await?;
    if !output.status.success() {
        return Err(format!(
            "curl {url}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

async fn curl_status(url: &str) -> Result<u16> {
    let output = Command::new("curl")
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", url])
        .output()
        .await?;
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

#[tokio::test(flavor = "multi_thread")]
async fn pulls_closure_and_serves_identically_afterwards() -> Result<()> {
    let upstream = Upstream::start(Duration::ZERO).await?;
    let cache = PullThroughCache::start(&upstream, false).await?;

    let dep = Published {
        compression: "zstd",
        ..Published::new(1, "dep", "dependency contents")
    };
    let mut top = Published {
        compression: "xz",
        ..Published::new(2, "top", "top contents")
    };
    top.references = vec![dep.base.clone(), top.base.clone()];
    upstream.publish(&cache.store_dir, &dep).await?;
    upstream.publish(&cache.store_dir, &top).await?;

    // The cold narinfo is in harmonia's own format, with upstream sigs.
    let cold = cache.narinfo(&top).await?;
    assert!(cold.contains("Compression: none\n"), "{cold}");
    assert!(
        cold.contains(&format!("?hash={}\n", top.hash())),
        "narinfo must point at harmonia's NAR route: {cold}"
    );
    assert!(cold.contains("Sig: cache.example.com-1:"), "{cold}");
    assert!(cold.contains(&format!("References: {} {}", dep.base, top.base)));
    // A narinfo request alone downloads nothing.
    assert_eq!(upstream.requests(&top.nar_path()), 0);

    // Only the top path is requested; the import pulls its reference.
    let nar = cache.nar_for(&cold).await?;
    assert_eq!(nar, nar_of_file(&top.contents));
    cache.wait_valid(&top).await?;
    assert!(cache.is_valid(&dep).await?);
    assert!(
        cache
            .signatures(&top)
            .await?
            .contains("cache.example.com-1:"),
        "upstream signature must be kept"
    );

    // Each NAR crossed the network exactly once.
    assert_eq!(upstream.requests(&top.nar_path()), 1);
    assert_eq!(upstream.requests(&dep.nar_path()), 1);

    // Warm: served from the local store, same narinfo and same bytes.
    let warm = cache.narinfo(&top).await?;
    assert_eq!(cold, warm);
    assert_eq!(cache.nar_for(&cold).await?, nar);
    assert_eq!(
        cache.nar_for(&cache.narinfo(&dep).await?).await?,
        nar_of_file(&dep.contents)
    );
    assert_eq!(upstream.requests(&top.nar_path()), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_clients_share_one_download() -> Result<()> {
    // ~2s per download, so all clients join while it runs.
    let upstream = Upstream::start(Duration::from_millis(25)).await?;
    let cache = PullThroughCache::start(&upstream, false).await?;
    let path = Published {
        compression: "bzip2",
        ..Published::new(3, "shared", vec![7u8; 1024 * 1024])
    };
    upstream.publish(&cache.store_dir, &path).await?;

    let narinfo = cache.narinfo(&path).await?;
    let url = cache.url(&format!("/{}", nar_url(&narinfo)?));
    let clients = (0..4)
        .map(|_| curl_command(&url).output())
        .collect::<Vec<_>>();
    let expected = nar_of_file(&path.contents);
    for output in futures_util::future::join_all(clients).await {
        let output = output?;
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, expected);
    }
    cache.wait_valid(&path).await?;
    assert_eq!(upstream.requests(&path.nar_path()), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_signature_is_served_but_not_imported() -> Result<()> {
    let upstream = Upstream::start(Duration::ZERO).await?;
    let cache = PullThroughCache::start(&upstream, false).await?;
    let path = Published {
        key: UNTRUSTED_SECRET_KEY,
        ..Published::new(4, "untrusted", "contents")
    };
    upstream.publish(&cache.store_dir, &path).await?;

    // The client gets correct bytes and does its own signature check.
    let nar = cache.nar_for(&cache.narinfo(&path).await?).await?;
    assert_eq!(nar, nar_of_file(&path.contents));
    // The daemon refuses the import.
    sleep(Duration::from_secs(3)).await;
    assert!(!cache.is_valid(&path).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_nar_fails_the_stream() -> Result<()> {
    let upstream = Upstream::start(Duration::ZERO).await?;
    let cache = PullThroughCache::start(&upstream, false).await?;
    let path = Published {
        corrupt: true,
        ..Published::new(5, "corrupt", vec![1u8; 300 * 1024])
    };
    upstream.publish(&cache.store_dir, &path).await?;

    let narinfo = cache.narinfo(&path).await?;
    assert!(cache.nar_for(&narinfo).await.is_err());
    sleep(Duration::from_secs(1)).await;
    assert!(!cache.is_valid(&path).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn upstreams_are_tried_in_order() -> Result<()> {
    let first = Upstream::start(Duration::ZERO).await?;
    let second = Upstream::start(Duration::ZERO).await?;
    let cache = PullThroughCache::start_with(&[&first, &second], false, &[]).await?;
    let only_second = Published::new(10, "second", "from the second upstream");
    let both = Published::new(11, "both", "on both upstreams");
    second.publish(&cache.store_dir, &only_second).await?;
    first.publish(&cache.store_dir, &both).await?;
    second.publish(&cache.store_dir, &both).await?;

    let nar = cache.nar_for(&cache.narinfo(&only_second).await?).await?;
    assert_eq!(nar, nar_of_file(&only_second.contents));
    assert_eq!(second.requests(&only_second.nar_path()), 1);

    cache.nar_for(&cache.narinfo(&both).await?).await?;
    assert_eq!(first.requests(&both.nar_path()), 1);
    assert_eq!(second.requests(&format!("/{}.narinfo", both.hash())), 0);
    cache.wait_valid(&only_second).await?;
    cache.wait_valid(&both).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_everywhere_is_404() -> Result<()> {
    let upstream = Upstream::start(Duration::ZERO).await?;
    let cache = PullThroughCache::start(&upstream, false).await?;
    let path = Published::new(6, "missing", "x");
    let hash = path.hash();
    assert_eq!(
        curl_status(&cache.url(&format!("/{hash}.narinfo"))).await?,
        404
    );
    let narhash = "0".repeat(52);
    assert_eq!(
        curl_status(&cache.url(&format!("/nar/{narhash}.nar?hash={hash}"))).await?,
        404
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_narhash_in_url_is_404() -> Result<()> {
    let upstream = Upstream::start(Duration::ZERO).await?;
    let cache = PullThroughCache::start(&upstream, false).await?;
    let path = Published::new(7, "p", "x");
    upstream.publish(&cache.store_dir, &path).await?;
    let narhash = "0".repeat(52);
    let url = cache.url(&format!("/nar/{narhash}.nar?hash={}", path.hash()));
    assert_eq!(curl_status(&url).await?, 404);
    assert_eq!(upstream.requests(&path.nar_path()), 0);
    Ok(())
}

/// Start a NAR download through `cache` and disconnect after one second.
async fn disconnecting_client(cache: &PullThroughCache, path: &Published) -> Result<()> {
    let narinfo = cache.narinfo(path).await?;
    let url = cache.url(&format!("/{}", nar_url(&narinfo)?));
    let status = Command::new("curl")
        .args(["-s", "-o", "/dev/null", "--max-time", "1", &url])
        .status()
        .await?;
    assert!(!status.success(), "the download should not finish in 1s");
    Ok(())
}

/// About 8s per download (512 KiB in 16 KiB chunks, 250ms apart).
fn slow_path(n: u32) -> Published {
    Published {
        compression: "none",
        ..Published::new(n, "slow", vec![9u8; 512 * 1024])
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_keeps_downloading_by_default() -> Result<()> {
    let upstream = Upstream::start(Duration::from_millis(250)).await?;
    let cache = PullThroughCache::start(&upstream, false).await?;
    let path = slow_path(8);
    upstream.publish(&cache.store_dir, &path).await?;

    disconnecting_client(&cache, &path).await?;
    cache.wait_valid(&path).await?;
    assert_eq!(upstream.completed(&path.nar_path()), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_cancels_download_when_enabled() -> Result<()> {
    // ~32s per download: well past the 10s grace period.
    let upstream = Upstream::start(Duration::from_millis(1000)).await?;
    let cache = PullThroughCache::start(&upstream, true).await?;
    let path = slow_path(9);
    upstream.publish(&cache.store_dir, &path).await?;

    disconnecting_client(&cache, &path).await?;
    // Grace period, cancel poll and the upstream noticing the hang-up.
    timeout(Duration::from_secs(25), async {
        while upstream.aborted(&path.nar_path()) == 0 {
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| "the upstream download was not cancelled")?;
    assert_eq!(upstream.completed(&path.nar_path()), 0);
    assert!(!cache.is_valid(&path).await?);
    Ok(())
}

/// A CA store holding only `pem`: `SSL_CERT_FILE` plus an empty
/// `SSL_CERT_DIR`. Both must be set, because cargo exports the system
/// locations into the environment of everything it runs.
struct CaStore {
    _dir: CanonicalTempDir,
    file: PathBuf,
    certs_dir: PathBuf,
}

impl CaStore {
    fn new(pem: &str) -> Result<Self> {
        let dir = CanonicalTempDir::new()?;
        let file = dir.path().join("ca.pem");
        let certs_dir = dir.path().join("certs");
        std::fs::write(&file, pem)?;
        std::fs::create_dir(&certs_dir)?;
        Ok(Self {
            _dir: dir,
            file,
            certs_dir,
        })
    }

    fn env(&self) -> [(&'static str, &Path); 2] {
        [
            ("SSL_CERT_FILE", &self.file),
            ("SSL_CERT_DIR", &self.certs_dir),
        ]
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn https_upstream_is_verified_against_the_system_ca_store() -> Result<()> {
    let pki = TestPki::new()?;
    let upstream = Upstream::start_with(Duration::ZERO, Some(pki.acceptor.clone())).await?;
    let ca = CaStore::new(&pki.ca_pem)?;
    let cache = PullThroughCache::start_with(&[&upstream], false, &ca.env()).await?;
    let path = Published::new(12, "tls", "fetched over https");
    upstream.publish(&cache.store_dir, &path).await?;

    let nar = cache.nar_for(&cache.narinfo(&path).await?).await?;
    assert_eq!(nar, nar_of_file(&path.contents));
    cache.wait_valid(&path).await?;
    assert_eq!(upstream.requests(&path.nar_path()), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn https_upstream_with_an_unknown_ca_is_not_used() -> Result<()> {
    let upstream = Upstream::start_with(Duration::ZERO, Some(TestPki::new()?.acceptor)).await?;
    let other_ca = CaStore::new(&TestPki::new()?.ca_pem)?;
    let cache = PullThroughCache::start_with(&[&upstream], false, &other_ca.env()).await?;
    let path = Published::new(13, "tls", "x");
    upstream.publish(&cache.store_dir, &path).await?;

    let narinfo_url = cache.url(&format!("/{}.narinfo", path.hash()));
    assert_eq!(curl_status(&narinfo_url).await?, 404);
    // The handshake failed, so no request reached the upstream.
    assert_eq!(upstream.requests(&format!("/{}.narinfo", path.hash())), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn https_upstream_without_ca_certificates_fails_startup() -> Result<()> {
    let upstream = Upstream::start_with(Duration::ZERO, Some(TestPki::new()?.acceptor)).await?;
    let empty = CaStore::new("")?;
    let started = PullThroughCache::start_with(&[&upstream], false, &empty.env()).await;
    assert!(started.is_err(), "harmonia must refuse to start");
    Ok(())
}
