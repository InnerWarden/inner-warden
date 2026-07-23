# CJC-090 compatibility record

Status: normative compatibility interpretation for the frozen baseline. This
record does not close acceptance or Proof gates by itself.

## Identity migration

An earlier planning draft combined contract identity and version and used shorter
journey identifiers. The tracked baseline normalizes those independent concepts:

| Concept | Earlier draft shape | Tracked v1 shape |
| --- | --- | --- |
| Contract identity | identity/version were combined | `contract_id: CJC-090` |
| Immutable version | identity/version were combined | `version: CJC-090-v1` |
| Journey identity | `J001` through `J012` | `CJC-090-J001` through `CJC-090-J012` |
| Acceptance identity | local short identifiers | `CJC-090-AT-001` through `CJC-090-AT-012` |

The migration changes identifiers, not expected behaviour or acceptance results.
Historical links may retain a legacy label as provenance, but new normative
references use the normalized identifiers and exact tracked digest. No successor
may silently renumber journeys or rewrite prior evidence.

## J006 and FR-049

`CJC-090-J006` preserves the Community local CLI allow, mute, and review-control
journey at the pinned baseline. Its `requirement_refs` includes FR-049 because
the earlier planning taxonomy grouped user-impacting policy controls with future
privileged-action governance. That reference does **not** make the baseline CLI
operation an Enterprise privileged action and does not apply `PAAM-090-v1`
retroactively.

The compatibility rule is:

1. Community allow/mute add, list, and remove keep their pinned local CLI
   semantics, user attribution, persistence, and narrow matching tests.
2. The Community dashboard remains read-only and may only reflect resulting
   provenance; it cannot mutate allow, mute, or review policy.
3. New Enterprise HTTP state changes require an exact published PAAM entry,
   authenticated scope, bound short-lived preview, typed confirmation, reason,
   audit, and runtime convergence.
4. A future proposal to expose Community policy mutation over HTTP is a new
   contract change. It cannot inherit authority from this historical FR-049 link.

This resolution preserves the frozen Community behaviour while keeping the new
Enterprise control plane default-deny.
