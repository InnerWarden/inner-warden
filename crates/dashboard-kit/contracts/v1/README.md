# InnerWarden dashboard public contracts v1

This directory is the tracked public authority for the edition-neutral dashboard
contract vocabulary. It defines shapes and fail-closed rules shared by Community
and Enterprise. It is not an Enterprise policy bundle, a pilot result, or proof
that any protection journey passed.

## Authority and boundaries

- Community may implement the shared read-only projections on its loopback-local,
  unauthenticated dashboard boundary. It exposes no Enterprise write route.
- Enterprise implements shared projections and privileged operations behind the
  existing Active Defence authenticated TLS boundary. Bearer and Basic-over-TLS
  are the explicit compatibility profiles; this contract does not permit Basic
  authentication over plaintext.
- Every OpenAPI operation declares Bearer OR Basic security explicitly. The
  Community exception is an adapter-only extension limited to the eight reviewed
  loopback-local read routes; it is never represented by an anonymous OpenAPI
  security branch or inherited by an Enterprise-only route.
- Exact `AM-090-v1` and `PAAM-090-v1` instances remain private Active Defence
  artifacts. Their public schemas are present here, but no instance, publisher,
  digest, authorization result, or customer evidence is invented here.
- A successful request receipt is not a verified runtime security outcome.
  Observe and Rehearse never support a containment claim.
- Stopping or expiring a canary converges to the verified zero-denial Rehearse
  mode; it does not restore an arbitrary request-supplied mode. Emergency
  disarm is the distinct transition to `disabled` / `disarmed`.

## Artifacts

| File | Authority |
| --- | --- |
| `dashboard-common-v1.schema.json` | Shared identity, scope, evidence, outcome, lifecycle, agent capability, metric, claim, egress and briefing vocabulary. |
| `dashboard-core-v1.openapi.yaml` | Same-origin read API and authenticated Enterprise evaluation/action API. |
| `community-journey-contract-v1.schema.json` | Frozen Community baseline shape and external digest-reference rules. |
| `CJC-090-v1.yaml` | Exact normalized Community baseline; expectations and open evidence gaps, never journey results. |
| `CJC-090-compatibility.md` | Auditable identity migration and the non-retroactive J006/FR-049 resolution. |
| `C1-contract-compatibility.md` | Fail-closed migration map from the pre-contract dashboard prototype to strict C0 vocabulary. |
| `assurance-matrix-v1.schema.json` | Public schema for private immutable Assurance Matrix instances. |
| `privileged-actions-v1.schema.json` | Public default-deny schema for private immutable PAAM instances and bound previews. |
| `enterprise-proof-report-v1.schema.json` | Proof shape whose generation/export remains gated. |

Feature-local `.specify` copies are planning inputs only and cannot authorize a
runtime action or support a protection or purchase claim.

## Version references and digests

Every normative reference carries four independent fields: `id`, `version`,
`canonicalization`, and a non-null lowercase `sha256:` digest. Missing, null,
malformed, mismatched, draft, mutable, unpublished, or unreviewed references fail
closed.

The frozen Community baseline is pinned as:

```text
id:               CJC-090
version:          CJC-090-v1
canonicalization: RAW-UTF8-BYTES-SHA256
digest:           sha256:5f4397b1c74409b06f5405f2ca4b748daea208a7d571abc3b03caf1c5040b62c
```

That digest is SHA-256 over the exact checked-in UTF-8 bytes of
`CJC-090-v1.yaml`. The byte-preserving rule is deliberate for this already-frozen
baseline and makes whitespace changes observable. It identifies contract bytes;
it does not turn `missing_evidence` into a pass.

New JSON documents use RFC 8785 JCS. YAML AM/PAAM instances are first converted
to the schema-defined data model and then RFC 8785 JCS before digesting, with the
digest field omitted as their schemas specify. A successor is a new immutable
version with actor, time, reason, predecessor, and field-level differences; it
never rewrites historical evidence.

RFC 8785 input is I-JSON. Normative AM/PAAM integer fields therefore stay within
JavaScript's exact safe-integer range (`±9007199254740991`). The same bound is
enforced for numeric Common and Dashboard API values that reach React; unbounded
counters use canonical, non-negative decimal strings without leading zeroes.

## CJC remediation and Proof gate

The tracked CJC has normalized identity `CJC-090`, version `CJC-090-v1`, and the
exact unique journey set `CJC-090-J001` through `CJC-090-J012`. Its compatibility
record preserves the earlier combined-identity/short-ID migration and scopes
J006 correctly.

`CJC-ID-REMEDIATION-001` is still an explicit release gate. Schema parsing,
exact-set validation, and an exact byte digest are necessary but not sufficient
to close it. Cross-review, bootstrap/Proof pinning by real consumers, private
AM/PAAM publication, and actual Community/pilot/hardening evidence remain
separate gates. Until every required gate is affirmatively supplied to the
semantic validator:

- Proof Report generation is disabled;
- Proof Report export is disabled;
- customer presentation and purchase recommendations are disabled.

No contract validator infers a journey, scenario, pilot, usability, enforcement,
or rollback result from a schema, source locator, command, screenshot, or digest.
Proof requires the exact ten ordered gates declared by the schema and Rust
validator; one absent or false gate disables generation and export.

## Validation

`cargo test -p innerwarden-dashboard-kit` performs 10 semantic unit tests and
20 contract-conformance tests for the public foundation:

- every JSON Schema passes the Draft 2020-12 meta-schema and compiles with the
  real `jsonschema` engine; all external/local references and every OpenAPI
  component/inline schema compile in one registered bundle;
- synthetic common-vocabulary plus complete AM, PAAM, and Enterprise Proof
  fixtures validate, while removal
  of required fields, unknown fields, changed constants, malformed formats, and
  malformed digests fail closed; checked-in negative fixtures also exercise
  freshness, host identity, metrics, capabilities, egress, briefing, Proof,
  duration, role, authenticated authorization, CSRF, action-specific confirmation,
  receipt convergence, rollback, canary-to-enforcement linkage, matrix reference
  resolution, expiry, canary-membership, and safe-number invariants;
- OpenAPI parses without duplicate YAML keys, uses unique operations, declares
  edition-aware authentication, and maps each privileged route to one known action;
- CJC identity, byte digest, exact twelve-journey set, and unique acceptance IDs match;
- malformed/missing/null/mismatched references, duplicate journeys, and unknown
  privileged actions fail closed;
- Proof export stays disabled whenever any remediation, publication, digest, or
  hardening gate is not explicitly closed; a passed scenario, verified action
  receipt, proved canary, rollback, or purchase precondition requires its own
  fresh runtime evidence and cannot be inferred from acknowledgement or a
  documented-but-unrun procedure.

The release workflow runs these checks as a dedicated contract-foundation gate.
