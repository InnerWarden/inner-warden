//! Embedded assets for the canonical white React dashboard.

use rust_embed::RustEmbed;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const BUNDLE_SCHEMA: &str = "innerwarden.dashboard.bundle.v1";
const BUNDLE_MANIFEST: &str = include_str!("../web/dist/bundle-manifest.json");

#[derive(RustEmbed)]
#[folder = "web/dist"]
struct DashboardAssets;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    schema: String,
    source_digest: String,
    entrypoint: String,
    assets: Vec<BundleAsset>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleAsset {
    path: String,
    sha256: String,
    size: u64,
}

static BUNDLE_VALIDATION: OnceLock<Result<(), String>> = OnceLock::new();

fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn referenced_assets(index: &str) -> Vec<&str> {
    let mut references = Vec::new();
    for marker in ["src=\"./", "href=\"./"] {
        let mut remaining = index;
        while let Some(start) = remaining.find(marker) {
            let value = &remaining[start + marker.len()..];
            let Some(end) = value.find('"') else {
                break;
            };
            let path = value[..end].split(['?', '#']).next().unwrap_or_default();
            if !references.contains(&path) {
                references.push(path);
            }
            remaining = &value[end + 1..];
        }
    }
    references.sort_unstable();
    references
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn content_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate_manifest_with<B: AsRef<[u8]>>(
    manifest_json: &str,
    assets: &BTreeMap<String, B>,
) -> Result<(), String> {
    let manifest: BundleManifest = serde_json::from_str(manifest_json)
        .map_err(|error| format!("invalid dashboard bundle manifest: {error}"))?;
    if manifest.schema != BUNDLE_SCHEMA {
        return Err(format!(
            "unsupported dashboard bundle schema: {}",
            manifest.schema
        ));
    }
    if !valid_sha256(&manifest.source_digest) {
        return Err(
            "dashboard bundle source digest must be 64 lowercase hex characters".to_owned(),
        );
    }
    if manifest.entrypoint != "index.html" || !safe_relative_path(&manifest.entrypoint) {
        return Err("dashboard bundle entrypoint must be index.html".to_owned());
    }
    if !assets.contains_key(&manifest.entrypoint) {
        return Err("dashboard bundle entrypoint is missing".to_owned());
    }

    let manifest_paths: Vec<&str> = manifest
        .assets
        .iter()
        .map(|asset| asset.path.as_str())
        .collect();
    if manifest_paths.is_empty() || manifest_paths.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("dashboard bundle assets must be sorted and unique".to_owned());
    }
    for asset in &manifest.assets {
        if asset.path == "bundle-manifest.json" || !safe_relative_path(&asset.path) {
            return Err(format!(
                "unsafe dashboard bundle asset path: {}",
                asset.path
            ));
        }
        if !valid_sha256(&asset.sha256) {
            return Err(format!(
                "dashboard bundle asset digest is invalid: {}",
                asset.path
            ));
        }
    }
    let embedded_paths: Vec<&str> = assets.keys().map(String::as_str).collect();
    if manifest_paths != embedded_paths {
        return Err("dashboard bundle inventory does not match embedded files".to_owned());
    }
    for asset in &manifest.assets {
        let bytes = assets
            .get(&asset.path)
            .expect("exact inventory comparison established the asset")
            .as_ref();
        if bytes.len() as u64 != asset.size {
            return Err(format!(
                "dashboard bundle asset size mismatch: {}",
                asset.path
            ));
        }
        if content_sha256(bytes) != asset.sha256 {
            return Err(format!(
                "dashboard bundle asset digest mismatch: {}",
                asset.path
            ));
        }
    }

    let index_html = std::str::from_utf8(
        assets
            .get(&manifest.entrypoint)
            .expect("entrypoint presence checked")
            .as_ref(),
    )
    .map_err(|_| "dashboard bundle entrypoint is not UTF-8".to_owned())?;
    let references = referenced_assets(index_html);
    if references.is_empty() {
        return Err("dashboard bundle entrypoint does not reference built assets".to_owned());
    }
    for path in references {
        if !safe_relative_path(path) {
            return Err(format!("unsafe dashboard bundle asset path: {path}"));
        }
        if !assets.contains_key(path) {
            return Err(format!("dashboard bundle asset is missing: {path}"));
        }
    }
    Ok(())
}

/// Validate that the committed bundle has a deterministic source manifest and
/// every asset referenced by its entrypoint is embedded. Source-to-bundle
/// freshness is checked by `npm run bundle:check` before release compilation;
/// this second guard fails closed if the output is missing or incomplete.
pub fn validate_embedded_bundle() -> Result<(), String> {
    BUNDLE_VALIDATION
        .get_or_init(|| {
            let assets: BTreeMap<String, Cow<'static, [u8]>> = DashboardAssets::iter()
                .filter(|path| path.as_ref() != "bundle-manifest.json")
                .filter_map(|path| {
                    DashboardAssets::get(path.as_ref()).map(|file| (path.into_owned(), file.data))
                })
                .collect();
            validate_manifest_with(BUNDLE_MANIFEST, &assets)
        })
        .clone()
}

/// Return one dashboard asset without exposing the embedding implementation to
/// either server. No asset is served when the committed bundle fails its
/// integrity checks. The bytes are borrowed from the binary whenever possible.
pub fn get(path: &str) -> Option<Cow<'static, [u8]>> {
    if validate_embedded_bundle().is_err() {
        return None;
    }
    DashboardAssets::get(path).map(|file| file.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_assets() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            (
                "assets/app.js".to_owned(),
                b"import './validate.js';\n".to_vec(),
            ),
            (
                "assets/validate.js".to_owned(),
                b"export const valid = true;\n".to_vec(),
            ),
            (
                "index.html".to_owned(),
                br#"<script type="module" src="./assets/app.js"></script>"#.to_vec(),
            ),
        ])
    }

    fn fixture_manifest(assets: &BTreeMap<String, Vec<u8>>) -> String {
        let records: Vec<_> = assets
            .iter()
            .map(|(path, bytes)| {
                json!({
                    "path": path,
                    "sha256": content_sha256(bytes),
                    "size": bytes.len(),
                })
            })
            .collect();
        json!({
            "schema": BUNDLE_SCHEMA,
            "source_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "entrypoint": "index.html",
            "assets": records,
        })
        .to_string()
    }

    #[test]
    fn canonical_bundle_contains_the_spa_entrypoint() {
        assert_eq!(validate_embedded_bundle(), Ok(()));
        assert!(get("index.html").is_some());
    }

    #[test]
    fn altered_asset_content_is_rejected_before_assets_are_served() {
        let expected = fixture_assets();
        let manifest = fixture_manifest(&expected);
        let mut altered = expected;
        let bytes = altered.get_mut("assets/app.js").expect("fixture app asset");
        bytes[0] = b'X';
        let result = validate_manifest_with(&manifest, &altered);
        assert_eq!(
            result,
            Err("dashboard bundle asset digest mismatch: assets/app.js".to_owned())
        );
    }

    #[test]
    fn missing_transitive_chunk_is_rejected() {
        let expected = fixture_assets();
        let manifest = fixture_manifest(&expected);
        let mut missing = expected;
        missing.remove("assets/validate.js");
        assert_eq!(
            validate_manifest_with(&manifest, &missing),
            Err("dashboard bundle inventory does not match embedded files".to_owned())
        );
    }

    #[test]
    fn unmanifested_extra_asset_is_rejected() {
        let expected = fixture_assets();
        let manifest = fixture_manifest(&expected);
        let mut extra = expected;
        extra.insert("assets/extra.js".to_owned(), b"extra\n".to_vec());
        assert_eq!(
            validate_manifest_with(&manifest, &extra),
            Err("dashboard bundle inventory does not match embedded files".to_owned())
        );
    }

    #[test]
    fn unsafe_bundle_reference_is_rejected() {
        let mut assets = fixture_assets();
        assets.insert("../outside.js".to_owned(), b"outside\n".to_vec());
        assets.insert(
            "index.html".to_owned(),
            br#"<script type="module" src="./../outside.js"></script>"#.to_vec(),
        );
        let manifest = fixture_manifest(&assets);
        assert_eq!(
            validate_manifest_with(&manifest, &assets),
            Err("unsafe dashboard bundle asset path: ../outside.js".to_owned())
        );
    }
}
