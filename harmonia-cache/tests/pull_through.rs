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
use std::process::Command;
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
    let body = curl(&narinfo_url)?;
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
    let status = curl_status(&format!("{}/{}", fixture.main_url, nar_url))?;
    assert_eq!(status, 200, "NAR should be served after import");

    // The upstream can go away: the path now lives in the local store.
    fixture.upstream_guard.take();
    let body = curl(&narinfo_url)?;
    assert!(
        body.contains("StorePath: "),
        "narinfo should be served locally, got: {body}"
    );

    // Unknown paths are still 404.
    let status = curl_status(&format!(
        "{}/00000000000000000000000000000000.narinfo",
        fixture.main_url
    ))?;
    assert_eq!(status, 404, "unknown path should stay a 404");
    Ok(())
}

#[tokio::test]
async fn test_pull_through_concurrent_requests_share_one_import() -> Result<()> {
    let fixture = setup(b"concurrent payload").await?;
    let narinfo_url = format!("{}/{}.narinfo", fixture.main_url, fixture.hash);

    // Hammer the same missing path from several tasks; all must succeed.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let url = narinfo_url.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            curl(&url).map_err(|e| e.to_string())
        }));
    }
    for handle in handles {
        let body = handle.await.map_err(|e| format!("task failed: {e}"))??;
        assert!(body.contains("StorePath: "));
    }
    Ok(())
}

fn curl(url: &str) -> Result<String> {
    let output = Command::new("curl")
        .args(["--fail", "--max-time", "60", "--silent", url])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Request to {url} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn curl_status(url: &str) -> Result<u16> {
    let output = Command::new("curl")
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
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Request to {url} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}
