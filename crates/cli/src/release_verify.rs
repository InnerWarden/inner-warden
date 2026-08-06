//! Verify a downloaded release artifact against the key compiled into THIS binary.
//!
//! # Why this exists (audit SEC-01)
//!
//! `upgrade` used to fetch `https://innerwarden.com/free` and pipe it to `sh`.
//! The Ed25519 pin it relied on lived INSIDE that downloaded script, so the
//! trust anchor travelled with the artifact it was supposed to authenticate:
//! whoever could serve you the script could serve you its key, and the check
//! passed either way. That is an unsafe update, not a signed one.
//!
//! The already-trusted binary is the right anchor. It is on disk because a human
//! decided to install it, and it can carry the key. So verification moves here:
//! the updater downloads the artifact and its sidecars and checks them against
//! [`RELEASE_PUBLIC_KEY_B64`], compiled in at build time. Nothing downloaded is
//! ever executed to decide whether what was downloaded is trustworthy.
//!
//! # The signature covers the DIGEST, not the file
//!
//! The release signs `sha256(binary)` rather than the binary itself:
//!
//! ```text
//! openssl dgst -sha256 -binary <bin> > digest
//! openssl pkeyutl -sign -inkey key.pem -rawin -in digest | base64 -w0 > <bin>.sig
//! ```
//!
//! So the verifier must hash first and verify the 32-byte digest as the message.
//! Verifying the file bytes directly would reject every genuine release, which is
//! why [`verify_release`] checks the `.sha256` sidecar AND the signature over the
//! digest: the first says "these are the bytes the release meant", the second
//! says "the release meant them".

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Raw 32-byte Ed25519 public key of the release signer, base64.
///
/// Same key the installer pins, vendored HERE so an update can be verified
/// without trusting anything fetched at update time. Overridable at build time
/// for a fork or a test release; unset means this value.
pub const RELEASE_PUBLIC_KEY_B64: &str = match option_env!("IW_RELEASE_PUBKEY_B64") {
    Some(k) => k,
    None => "vR3bZQMGNQ7tfoKirl4mbBCE6DekmmEFADL5g984PC4=",
};

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The binary does not hash to what the `.sha256` sidecar claims.
    DigestMismatch,
    /// The sidecar was not the expected shape (hex digest, optionally followed
    /// by the filename, as `sha256sum` writes it).
    MalformedDigest,
    /// The `.sig` sidecar was not valid base64, or not 64 bytes.
    MalformedSignature,
    /// Well-formed, and not a signature by the pinned key over these bytes.
    BadSignature,
    /// The compiled-in key is not a usable Ed25519 public key. A build problem,
    /// not something an attacker can cause at update time.
    BadPinnedKey,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::DigestMismatch => "the downloaded bytes do not match the published SHA-256",
            Self::MalformedDigest => "the .sha256 sidecar is malformed",
            Self::MalformedSignature => "the .sig sidecar is malformed",
            Self::BadSignature => "the signature is not valid for these bytes",
            Self::BadPinnedKey => "this build carries an invalid release public key",
        };
        f.write_str(msg)
    }
}

/// Parse a `sha256sum`-style sidecar into its hex digest.
///
/// Accepts both `<hex>` and `<hex>  <filename>`, which is what the release
/// produces, and rejects anything that is not exactly 64 hex characters. A
/// lenient parse here would let a truncated sidecar silently weaken the check.
pub fn parse_digest_sidecar(raw: &str) -> Option<[u8; 32]> {
    let hex = raw.split_whitespace().next()?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Verify `bytes` against the published `.sha256` and `.sig` sidecars.
///
/// Fails closed on every path: a missing, malformed or mismatched sidecar is an
/// error, never a skipped check.
pub fn verify_release(
    bytes: &[u8],
    sha256_sidecar: &str,
    sig_sidecar: &str,
) -> Result<(), VerifyError> {
    let expected = parse_digest_sidecar(sha256_sidecar).ok_or(VerifyError::MalformedDigest)?;
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    // Compare the digest BEFORE touching the signature: it is the cheaper check
    // and it gives the clearer error when a download simply truncated.
    if actual != expected {
        return Err(VerifyError::DigestMismatch);
    }

    let key_raw = base64::engine::general_purpose::STANDARD
        .decode(RELEASE_PUBLIC_KEY_B64.trim())
        .map_err(|_| VerifyError::BadPinnedKey)?;
    let key_bytes: [u8; 32] = key_raw.try_into().map_err(|_| VerifyError::BadPinnedKey)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerifyError::BadPinnedKey)?;

    let sig_raw = base64::engine::general_purpose::STANDARD
        .decode(sig_sidecar.trim())
        .map_err(|_| VerifyError::MalformedSignature)?;
    let sig_bytes: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| VerifyError::MalformedSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // The release signs the DIGEST, so the digest is the message.
    key.verify_strict(&actual, &signature)
        .map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a signed artifact the way the release workflow does: sign the
    /// sha256 digest, not the file.
    fn signed(bytes: &[u8], key: &SigningKey) -> (String, String) {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let sha = format!("{}  innerwarden-linux-x86_64", hex(&digest));
        let sig = base64::engine::general_purpose::STANDARD.encode(key.sign(&digest).to_bytes());
        (sha, sig)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn with_pinned_key(key: &SigningKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
    }

    /// Verify against an explicitly supplied key, mirroring `verify_release`
    /// with the pin swapped, so the tests do not depend on the production key.
    fn verify_with(
        pubkey_b64: &str,
        bytes: &[u8],
        sha: &str,
        sig: &str,
    ) -> Result<(), VerifyError> {
        let expected = parse_digest_sidecar(sha).ok_or(VerifyError::MalformedDigest)?;
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if actual != expected {
            return Err(VerifyError::DigestMismatch);
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(pubkey_b64)
            .map_err(|_| VerifyError::BadPinnedKey)?;
        let kb: [u8; 32] = raw.try_into().map_err(|_| VerifyError::BadPinnedKey)?;
        let key = VerifyingKey::from_bytes(&kb).map_err(|_| VerifyError::BadPinnedKey)?;
        let sr = base64::engine::general_purpose::STANDARD
            .decode(sig.trim())
            .map_err(|_| VerifyError::MalformedSignature)?;
        let sb: [u8; 64] = sr.try_into().map_err(|_| VerifyError::MalformedSignature)?;
        key.verify_strict(&actual, &Signature::from_bytes(&sb))
            .map_err(|_| VerifyError::BadSignature)
    }

    #[test]
    fn a_genuine_release_verifies() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = b"the real binary";
        let (sha, sig) = signed(bytes, &key);
        assert_eq!(
            verify_with(&with_pinned_key(&key), bytes, &sha, &sig),
            Ok(())
        );
    }

    /// REGRESSION ANCHOR for SEC-01. A tampered binary must be refused even
    /// though its sidecars are well formed, which is the whole point of moving
    /// the anchor into the binary: previously the check could be satisfied by
    /// whoever served the download.
    #[test]
    fn a_tampered_binary_is_refused() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (sha, sig) = signed(b"the real binary", &key);
        assert_eq!(
            verify_with(&with_pinned_key(&key), b"a swapped binary", &sha, &sig),
            Err(VerifyError::DigestMismatch)
        );
    }

    /// The attack the co-located anchor allowed: an attacker signs their own
    /// artifact with their own key and ships a matching sidecar. Consistent with
    /// itself, and rejected, because the key is ours and not theirs.
    #[test]
    fn an_artifact_signed_by_another_key_is_refused() {
        let ours = SigningKey::from_bytes(&[7u8; 32]);
        let theirs = SigningKey::from_bytes(&[9u8; 32]);
        let bytes = b"attacker payload";
        let (sha, sig) = signed(bytes, &theirs);
        assert_eq!(
            verify_with(&with_pinned_key(&ours), bytes, &sha, &sig),
            Err(VerifyError::BadSignature),
            "a self-consistent artifact signed by the wrong key must not pass"
        );
    }

    /// Every malformed input is an error, never a skipped check.
    #[test]
    fn malformed_sidecars_fail_closed() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = b"x";
        let (sha, sig) = signed(bytes, &key);
        let pin = with_pinned_key(&key);

        assert_eq!(
            verify_with(&pin, bytes, "", &sig),
            Err(VerifyError::MalformedDigest)
        );
        assert_eq!(
            verify_with(&pin, bytes, "not-a-digest", &sig),
            Err(VerifyError::MalformedDigest)
        );
        // A truncated digest must not be accepted as a prefix match.
        assert_eq!(
            verify_with(&pin, bytes, &sha[..40], &sig),
            Err(VerifyError::MalformedDigest)
        );
        assert_eq!(
            verify_with(&pin, bytes, &sha, "!!!not base64!!!"),
            Err(VerifyError::MalformedSignature)
        );
        assert_eq!(
            verify_with(&pin, bytes, &sha, "c2hvcnQ="),
            Err(VerifyError::MalformedSignature),
            "a signature of the wrong length is malformed, not merely invalid"
        );
    }

    /// The sidecar the release actually writes is `<hex>  <filename>`; a bare
    /// digest is accepted too. Both must parse to the same value.
    #[test]
    fn the_sidecar_format_the_release_writes_is_accepted() {
        let digest = [0xabu8; 32];
        let bare = hex(&digest);
        let named = format!("{bare}  innerwarden-macos-aarch64");
        assert_eq!(parse_digest_sidecar(&bare), Some(digest));
        assert_eq!(parse_digest_sidecar(&named), Some(digest));
        assert_eq!(parse_digest_sidecar("  "), None);
    }

    /// The key shipped in this build must be a usable Ed25519 key, so a bad
    /// vendored pin is caught here and not by an operator whose upgrade fails.
    #[test]
    fn the_compiled_in_key_is_a_valid_ed25519_key() {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(RELEASE_PUBLIC_KEY_B64)
            .expect("pinned key must be base64");
        let bytes: [u8; 32] = raw.try_into().expect("pinned key must be 32 bytes");
        assert!(
            VerifyingKey::from_bytes(&bytes).is_ok(),
            "pinned key must be a valid Ed25519 public key"
        );
    }
}
