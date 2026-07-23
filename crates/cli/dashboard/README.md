# Dashboard command compatibility

The canonical React source and committed bundle now live in
`../../dashboard-kit/web`. This directory intentionally contains no duplicate
frontend source. It preserves the pre-extraction release command:

```sh
cd crates/cli/dashboard
npm ci
npm run build
```

The shim installs and builds the canonical package. A Cargo `build.rs` is not
used because Community Rust builds must remain offline-capable and portable to
Linux, macOS, and Windows without requiring Node. Bundle freshness is enforced
by the deterministic source fingerprint and exact per-file hashes/sizes in
`dist/bundle-manifest.json`, the `bundle:check` script, and the Linux dashboard
CI/release jobs before any cross-platform binary is published.
