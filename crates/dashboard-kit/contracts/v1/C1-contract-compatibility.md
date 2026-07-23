# C1 prototype to C0 public-contract compatibility map

Status: normative migration boundary for consumers of the pre-contract C1
dashboard prototype. The prototype is not an alternate authority and does not
weaken the C0 contract.

## Migration rule

C0 is strict by design. A legacy C1 payload is accepted only after an explicit
adapter produces every required C0 field, validates the result against the
tracked Draft 2020-12 schema, and preserves evidence provenance. A missing,
null, stale, ambiguous, or unverified mapping remains unavailable or
unattributed. It never becomes a protection claim, a privileged-action grant,
or a verified runtime outcome.

| Concept | C1 prototype shape | C0 public contract | Required adapter behavior |
| --- | --- | --- | --- |
| `VersionRef` | `id`, `version`, and a nullable digest | `id`, `version`, `canonicalization`, and a non-null `sha256:` digest | Resolve a known immutable artifact and its canonicalization; otherwise fail closed. Never drop or nullable-relax C0 fields. |
| `ScopeRef.evidence` | Scope label and verification may appear without evidence | `display_name` is nullable, `verification` includes `unattributed`, and `evidence` is required | Preserve the legacy label as display-only data. Supply real evidence references or an empty list with `unattributed`; do not infer verification. |
| `EvidenceRef.freshness` | A source string/version and receive time may stand in for freshness | Structured `SourceRef` plus `EvidenceFreshness { observed_at, budget_seconds, state, age_seconds }` | Normalize source provenance and calculate freshness only from an observed timestamp and declared budget. A receive time remains transport metadata, not canonical observation time. |
| `PrivacyBoundary` / egress | Egress may be represented as a free-form string | Structured egress paths with destination class, purpose, data classes, state, consent, retention, redaction, local fallback, and evidence | Map only explicitly known fields. Unknown destinations, consent, retention, or evidence remain visible as unknown/unavailable; never infer “local only.” |
| `ClaimRecord` | Prototype claims may be tied only to an assurance-matrix reference | A claim has a statement or semantic key, immutable version refs, population, environment, review/expiry fields, scope, action classes, evidence, and limitations | Migrate provenance and limitations explicitly. A prototype claim without the complete review/evidence context stays `unverified`. |
| `AgentSubject.sessions` | Sessions may be absent | `sessions` is required and carries bounded session identity/scope metadata | Use an empty list when no session evidence exists. Do not synthesize active sessions. |

## Compatibility invariant

The adapter direction is C1 to C0 only. C0 schemas, OpenAPI operations, AM/PAAM
publication rules, and Proof gates are not changed to mirror a prototype. Once a
producer emits C0 directly, the compatibility adapter is bypassed and the same
validators remain authoritative.
