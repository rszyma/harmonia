//! Pull-through tests: a miss is fetched from `upstream_caches` and imported
//! into the local store, so later requests are served locally.
//!
//! Both servers share one store directory (like two views of `/nix/store` in
//! production) but keep separate state databases, so the main cache starts
//! out missing the path.

mod common;

use common::{
    CanonicalTempDir, init_local_store, pick_unused_port, start_harmonia_cache,
    start_harmonia_cache_with_env,
};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tempfile::NamedTempFile;

const SIGNING_KEY: &str = include_str!("../../tests/cache.sk");
const PUBLIC_KEY: &str = include_str!("../../tests/cache.pk");

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn write_temp_file(content: &str) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    write!(file, "{content}")?;
    file.flush()?;
    Ok(file)
}

fn store_url(store_dir: &Path, state_dir: &Path) -> String {
    format!(
        "local?store={}&state={}",
        store_dir.display(),
        state_dir.display()
    )
}

/// Add a file to a chroot store, returning `(store_path, hash_part)`.
fn add_to_store(store_dir: &Path, state_dir: &Path, content: &[u8]) -> Result<(String, String)> {
    let dir = CanonicalTempDir::new()?;
    let file_path = dir.path().join("payload.bin");
    fs::write(&file_path, content)?;
    let output = Command::new("nix-store")
        .args([
            "--add",
            &file_path.to_string_lossy(),
            "--store",
            &store_url(store_dir, state_dir),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "nix-store --add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let path = String::from_utf8(output.stdout)?.trim().to_string();
    let file_name = path.rsplit('/').next().ok_or("no file name")?.to_string();
    let hash = file_name
        .get(..32)
        .ok_or("store path hash too short")?
        .to_string();
    Ok((path, hash))
}

struct Fixture {
    _temp_dir: CanonicalTempDir,
    hash: String,
    main_url: String,
    upstream_guard: Option<Box<dyn Send>>,
    _main_guard: Box<dyn Send>,
    _key_file: NamedTempFile,
}

async fn setup(payload: &[u8]) -> Result<Fixture> {
    let temp_dir = CanonicalTempDir::new()?;
    let root = temp_dir.path().to_path_buf();
    let store_dir = root.join("store");
    let upstream_state = root.join("var-upstream/nix");
    let main_state = root.join("var-main/nix");
    init_local_store(&store_dir, &upstream_state)?;
    init_local_store(&store_dir, &main_state)?;

    let (_upstream_path, hash) = add_to_store(&store_dir, &upstream_state, payload)?;

    let key_file = write_temp_file(SIGNING_KEY.trim())?;
    let upstream_port = pick_unused_port().ok_or("No available ports")?;
    let upstream_config = format!(
        "bind = \"127.0.0.1:{upstream_port}\"\n\
         nix_db_path = \"{db}\"\n\
         sign_key_paths = [\"{key}\"]\n\
         virtual_nix_store = \"{store}\"\n\
         real_nix_store = \"{store}\"\n",
        db = upstream_state.join("db/db.sqlite").display(),
        key = key_file.path().display(),
        store = store_dir.display(),
    );
    let upstream_guard = start_harmonia_cache(&upstream_config, upstream_port).await?;
    let upstream_url = format!("http://127.0.0.1:{upstream_port}");

    let main_port = pick_unused_port().ok_or("No available ports")?;
    let main_config = format!(
        "bind = \"127.0.0.1:{main_port}\"\n\
         nix_db_path = \"{db}\"\n\
         virtual_nix_store = \"{store}\"\n\
         real_nix_store = \"{store}\"\n\
         upstream_caches = [\"{upstream_url}\"]\n",
        db = main_state.join("db/db.sqlite").display(),
        store = store_dir.display(),
    );
    let main_guard = start_harmonia_cache_with_env(
        &main_config,
        main_port,
        &[(
            "NIX_CONFIG",
            &format!("trusted-public-keys = {}", PUBLIC_KEY.trim()),
        )],
    )
    .await?;

    Ok(Fixture {
        _temp_dir: temp_dir,
        hash,
        main_url: format!("http://127.0.0.1:{main_port}"),
        upstream_guard: Some(upstream_guard),
        _main_guard: main_guard,
        _key_file: key_file,
    })
}

#[tokio::test]
async fn test_pull_through_imports_into_local_store() -> Result<()> {
    let mut fixture = setup(b"hello pull-through").await?;
    let narinfo_url = format!("{}/{}.narinfo", fixture.main_url, fixture.hash);

    // Miss becomes a hit: the narinfo is fetched upstream and imported.
    let body = curl(&narinfo_url).await?;
    assert!(
        body.contains("StorePath: "),
        "narinfo should name the store path, got: {body}"
    );
    // Signatures are copied from upstream, none are minted locally.
    assert!(
        body.contains("Sig: cache.example.com-1:"),
        "narinfo should carry the upstream signature, got: {body}"
    );

    // The NAR is served from the freshly imported local path.
    let nar_url = body
        .lines()
        .filter_map(|line| line.strip_prefix("URL: "))
        .next()
        .ok_or("narinfo has no URL")?;
    let status = curl_status(&format!("{}/{}", fixture.main_url, nar_url)).await?;
    assert_eq!(status, 200, "NAR should be served after import");

    // The upstream can go away: the path now lives in the local store.
    fixture.upstream_guard.take();
    let body = curl(&narinfo_url).await?;
    assert!(
        body.contains("StorePath: "),
        "narinfo should be served locally, got: {body}"
    );

    // Unknown paths are still 404.
    let status = curl_status(&format!(
        "{}/00000000000000000000000000000000.narinfo",
        fixture.main_url
    ))
    .await?;
    assert_eq!(status, 404, "unknown path should stay a 404");
    Ok(())
}

#[tokio::test]
async fn test_pull_through_concurrent_requests_share_one_import() -> Result<()> {
    let mut fixture = setup(b"concurrent payload").await?;
    let narinfo_url = format!("{}/{}.narinfo", fixture.main_url, fixture.hash);

    // One narinfo fetch names the canonical NAR; hammer that from several
    // tasks. All must stream the same bytes from a single pull+import.
    let body = curl(&narinfo_url).await?;
    let nar_path = nar_url_path_from(&body)?;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let url = format!("{}/{nar_path}", fixture.main_url);
        handles.push(tokio::spawn(async move {
            curl_bytes(&url).await.map_err(|e| e.to_string())
        }));
    }
    for handle in handles {
        let bytes = handle.await.map_err(|e| format!("task failed: {e}"))??;
        assert!(!bytes.is_empty());
    }
    // All readers saw the same pull: killing the upstream still leaves
    // the path served locally.
    tokio::time::sleep(Duration::from_secs(3)).await;
    fixture.upstream_guard.take();
    let body = curl(&narinfo_url).await?;
    assert!(body.contains("StorePath: "));
    Ok(())
}

/// A fake upstream that serves one signed narinfo verbatim (hit-counted)
/// and drips its NAR at ~320KB/s. Disconnect detection on the server is
/// write-driven: only flowing bytes reveal a dead reader, so a drip (not
/// a gate) is what lets the cancel path fire mid-download.
async fn run_slow_upstream(
    listener: tokio::net::TcpListener,
    narinfo: Vec<u8>,
    nar: Vec<u8>,
    hits: Arc<AtomicUsize>,
    nar_hits: Arc<AtomicUsize>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            break;
        };
        let narinfo = narinfo.clone();
        let nar = nar.clone();
        let hits = hits.clone();
        let nar_hits = nar_hits.clone();
        tokio::spawn(async move {
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        head.extend_from_slice(&buf[..n]);
                        if head.len() > 8192 || head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let path = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            if path.ends_with(".narinfo") {
                hits.fetch_add(1, Ordering::Relaxed);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/x-nix-narinfo\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    narinfo.len()
                );
                if sock.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                let _ = sock.write_all(&narinfo).await;
            } else {
                nar_hits.fetch_add(1, Ordering::Relaxed);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-nix-nar\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    nar.len()
                );
                if sock.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                if sock.flush().await.is_err() {
                    return;
                }
                // Drip the body: keeps the pull in flight for ~20s.
                let mut off = 0;
                while off < nar.len() {
                    let end = (off + 65536).min(nar.len());
                    if sock.write_all(&nar[off..end]).await.is_err() {
                        break;
                    }
                    if sock.flush().await.is_err() {
                        break;
                    }
                    off = end;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        });
    }
}

struct SlowFixture {
    _temp_dir: CanonicalTempDir,
    hash: String,
    main_url: String,
    nar_bytes: Vec<u8>,
    hits: Arc<AtomicUsize>,
    nar_hits: Arc<AtomicUsize>,
    slow_task: tokio::task::JoinHandle<()>,
    _main_guard: Box<dyn Send>,
    _key_file: NamedTempFile,
}

/// Real signed upstream for narinfo bytes + NAR content, but the main
/// cache pulls through a dripping slow server standing in front of it.
/// `url_override` rewrites the narinfo `URL:` line, simulating upstreams
/// (like cache.nixos.org) whose file names fall outside harmonia's own
/// URL scheme. The rewrite is signature-safe: signatures do not cover
/// the URL field (the import staging relies on the same fact).
async fn setup_slow(cancel_on_disconnect: bool, url_override: Option<&str>) -> Result<SlowFixture> {
    let temp_dir = CanonicalTempDir::new()?;
    let root = temp_dir.path().to_path_buf();
    let store_dir = root.join("store");
    let upstream_state = root.join("var-upstream/nix");
    let main_state = root.join("var-main/nix");
    init_local_store(&store_dir, &upstream_state)?;
    init_local_store(&store_dir, &main_state)?;

    // Multi-megabyte payload: at drip speed the pull stays in flight long
    // past the kill and the linger, so timing needs no precision.
    let (_upstream_path, hash) =
        add_to_store(&store_dir, &upstream_state, &vec![0xABu8; 6 * 1024 * 1024])?;

    let key_file = write_temp_file(SIGNING_KEY.trim())?;
    let upstream_port = pick_unused_port().ok_or("No available ports")?;
    let upstream_config = format!(
        "bind = \"127.0.0.1:{upstream_port}\"\n\
         nix_db_path = \"{db}\"\n\
         sign_key_paths = [\"{key}\"]\n\
         virtual_nix_store = \"{store}\"\n\
         real_nix_store = \"{store}\"\n",
        db = upstream_state.join("db/db.sqlite").display(),
        key = key_file.path().display(),
        store = store_dir.display(),
    );
    let _upstream_guard = start_harmonia_cache(&upstream_config, upstream_port).await?;
    let upstream_url = format!("http://127.0.0.1:{upstream_port}");

    // Signed narinfo and exact NAR bytes, straight from the real upstream.
    // The narinfo passes through the slow server byte-identical (apart
    // from the optional URL rewrite), so its signature stays valid and
    // recovery can import.
    let narinfo = String::from_utf8(curl_bytes(&format!("{upstream_url}/{hash}.narinfo")).await?)?;
    let nar_bytes = curl_bytes(&format!("{upstream_url}/{}", nar_url_path_from(&narinfo)?)).await?;
    let narinfo = if let Some(url) = url_override {
        narinfo
            .lines()
            .map(|line| {
                if line.starts_with("URL: ") {
                    format!("URL: {url}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    } else {
        narinfo
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let slow_port = listener.local_addr()?.port();
    let hits = Arc::new(AtomicUsize::new(0));
    let nar_hits = Arc::new(AtomicUsize::new(0));
    let slow_task = tokio::spawn(run_slow_upstream(
        listener,
        narinfo.into_bytes(),
        nar_bytes.clone(),
        hits.clone(),
        nar_hits.clone(),
    ));
    let slow_url = format!("http://127.0.0.1:{slow_port}");

    let main_port = pick_unused_port().ok_or("No available ports")?;
    let main_config = format!(
        "bind = \"127.0.0.1:{main_port}\"\n\
         nix_db_path = \"{db}\"\n\
         virtual_nix_store = \"{store}\"\n\
         real_nix_store = \"{store}\"\n\
         upstream_caches = [\"{slow_url}\"]\n\
         upstream_cancel_on_disconnect = {cancel_on_disconnect}\n",
        db = main_state.join("db/db.sqlite").display(),
        store = store_dir.display(),
    );
    let main_guard = start_harmonia_cache_with_env(
        &main_config,
        main_port,
        &[(
            "NIX_CONFIG",
            &format!("trusted-public-keys = {}", PUBLIC_KEY.trim()),
        )],
    )
    .await?;

    Ok(SlowFixture {
        _temp_dir: temp_dir,
        hash,
        main_url: format!("http://127.0.0.1:{main_port}"),
        nar_bytes,
        hits,
        nar_hits,
        slow_task,
        _main_guard: main_guard,
        _key_file: key_file,
    })
}

/// The `URL: ` line of a narinfo body (relative to the cache root).
fn nar_url_path_from(narinfo: &str) -> Result<String> {
    narinfo
        .lines()
        .filter_map(|line| line.strip_prefix("URL: "))
        .next()
        .map(str::to_string)
        .ok_or_else(|| "narinfo has no URL".into())
}

/// Async curl: blocking `std::process` calls would freeze the test's
/// current-thread executor while the in-test slow upstream needs polling.
async fn curl(url: &str) -> Result<String> {
    let output = tokio::process::Command::new("curl")
        .args(["--fail", "--max-time", "60", "--silent", url])
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!(
            "Request to {url} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

async fn curl_bytes(url: &str) -> Result<Vec<u8>> {
    let output = tokio::process::Command::new("curl")
        .args(["--fail", "--max-time", "60", "--silent", url])
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!(
            "Request to {url} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

/// Start a NAR download that the test can SIGKILL mid-transfer.
fn curl_spawn(url: &str) -> Result<tokio::process::Child> {
    Ok(tokio::process::Command::new("curl")
        .args(["--silent", "--max-time", "60", url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

#[tokio::test]
async fn test_pull_through_cancels_on_disconnect() -> Result<()> {
    let fix = setup_slow(true, None).await?;
    let narinfo_url = format!("{}/{}.narinfo", fix.main_url, fix.hash);

    // The narinfo alone spawns nothing: lazy pulls start at the NAR.
    let body = curl(&narinfo_url).await?;
    assert!(body.contains("StorePath: "));
    assert_eq!(fix.hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        fix.nar_hits.load(Ordering::Relaxed),
        0,
        "narinfo must not start the pull"
    );
    let nar_path = nar_url_path_from(&body)?;

    // Attach a reader, then disconnect it mid-download (drips ~20s).
    let mut reader = curl_spawn(&format!("{}/{nar_path}", fix.main_url))?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    reader.kill().await?;
    reader.wait().await?;

    // Outlive the 10s linger: the pull is abandoned, so the recovery
    // NAR request starts a fresh pull (second upstream NAR fetch).
    tokio::time::sleep(Duration::from_secs(15)).await;
    let got = curl_bytes(&format!("{}/{nar_path}", fix.main_url)).await?;
    assert_eq!(got, fix.nar_bytes);
    assert_eq!(
        fix.nar_hits.load(Ordering::Relaxed),
        2,
        "abandoned pull should trigger a fresh upstream fetch"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    fix.slow_task.abort();
    let body = curl(&narinfo_url).await?;
    assert!(
        body.contains("StorePath: "),
        "path should be served locally after recovery, got: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn test_pull_through_completes_without_readers_by_default() -> Result<()> {
    let fix = setup_slow(false, None).await?;
    let narinfo_url = format!("{}/{}.narinfo", fix.main_url, fix.hash);

    let body = curl(&narinfo_url).await?;
    let nar_path = nar_url_path_from(&body)?;
    let mut reader = curl_spawn(&format!("{}/{nar_path}", fix.main_url))?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    reader.kill().await?;
    reader.wait().await?;

    // Nobody ever reads again, but the default policy still finishes the
    // pull in the background: the NAR request below attaches to the
    // completed download (or the finished import) either way.
    tokio::time::sleep(Duration::from_secs(20)).await;
    let got = curl_bytes(&format!("{}/{nar_path}", fix.main_url)).await?;
    assert_eq!(got, fix.nar_bytes);
    tokio::time::sleep(Duration::from_secs(3)).await;
    fix.slow_task.abort();
    let body = curl(&narinfo_url).await?;
    assert!(
        body.contains("StorePath: "),
        "background pull should have imported the path, got: {body}"
    );
    Ok(())
}

/// Upstream file names need not match harmonia's `/nar/<hash>.nar` routes
/// (cache.nixos.org serves `nar/<file>.nar.zst`). The served narinfo
/// rewrites them to the canonical route, so the NAR request spawns the
/// pull instead of 404ing — no matter what the upstream named it.
#[tokio::test]
async fn test_pull_through_rewrites_upstream_filename() -> Result<()> {
    let fix = setup_slow(false, Some("nar/blob.bin")).await?;
    let narinfo_url = format!("{}/{}.narinfo", fix.main_url, fix.hash);

    let body = curl(&narinfo_url).await?;
    let nar_path = nar_url_path_from(&body)?;
    assert!(
        !body.contains("URL: nar/blob.bin"),
        "upstream filename must be rewritten, got: {body}"
    );
    assert!(
        nar_path.starts_with("nar/")
            && nar_path.contains(".nar?hash=")
            && nar_path.ends_with(&fix.hash),
        "narinfo should point at the canonical route, got: {nar_path}"
    );

    // The canonical NAR request spawns the pull and streams it — reusing
    // the memoized narinfo instead of re-fetching it.
    let got = curl_bytes(&format!("{}/{nar_path}", fix.main_url)).await?;
    assert_eq!(got, fix.nar_bytes);
    assert_eq!(
        fix.hits.load(Ordering::Relaxed),
        1,
        "serve and pull should share one upstream narinfo fetch"
    );

    // And the pull still imports normally.
    tokio::time::sleep(Duration::from_secs(3)).await;
    fix.slow_task.abort();
    let body = curl(&narinfo_url).await?;
    assert!(
        body.contains("StorePath: "),
        "path should be served locally after import, got: {body}"
    );
    Ok(())
}

async fn curl_status(url: &str) -> Result<u16> {
    let output = tokio::process::Command::new("curl")
        .args([
            "--max-time",
            "60",
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            url,
        ])
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!(
            "Request to {url} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}
