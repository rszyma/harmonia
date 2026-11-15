use crate::error::{CacheError, StoreError};
use actix_web::{HttpResponse, http, web};
use harmonia_store_nar_info::{build_narinfo, format_narinfo_txt};
use harmonia_store_path::StorePathHash;
use harmonia_store_path_info::StorePathKeyed;
use serde::Deserialize;

use crate::config::Config;
use crate::{cache_control_max_age_1d, some_or_404};

#[derive(Debug, Deserialize)]
pub struct Param {
    json: Option<String>,
}

pub(crate) async fn get(
    hash: web::Path<String>,
    param: web::Query<Param>,
    settings: web::Data<Config>,
) -> crate::ServerResult {
    let hash = hash.into_inner();
    // Reject malformed hash parts up front so the `path >= ?` index scan in
    // SQLite cannot be tricked into matching an unrelated store path.
    let store_path_hash = StorePathHash::decode_digest(hash.as_bytes()).map_err(|e| {
        CacheError::from(StoreError::PathQuery {
            hash: hash.clone(),
            reason: format!("Invalid hash format: {e}"),
        })
    })?;

    let local = settings
        .store
        .query_path_info_by_hash_part(&store_path_hash)?;
    let (info, sign_keys) = match local {
        Some(info) => (
            StorePathKeyed {
                path: info.path,
                info: info.info,
            },
            settings.secret_keys.as_slice(),
        ),
        // Not signed with our keys: the content is unverified until pulled.
        None if settings.pull_through.enabled() => (
            some_or_404!(crate::pull_through::narinfo(&settings, &store_path_hash).await),
            &[][..],
        ),
        None => some_or_404!(None),
    };
    let narinfo = build_narinfo(settings.store.store_dir(), info, &hash, sign_keys);

    if param.json.is_some() {
        // JSON format: return the full nar-info (upstream JSON v3 format).
        Ok(HttpResponse::Ok()
            .insert_header(cache_control_max_age_1d())
            .json(&narinfo.info))
    } else {
        let url = narinfo.info.url.clone().unwrap_or_default();
        let res = format_narinfo_txt(settings.store.store_dir(), &narinfo);
        Ok(HttpResponse::Ok()
            .insert_header((http::header::CONTENT_TYPE, "text/x-nix-narinfo"))
            .insert_header(("Nix-Link", url))
            .insert_header(cache_control_max_age_1d())
            .body(res))
    }
}
