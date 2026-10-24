# What this build checks, and what it does not (yet)

Written for honesty, not for show: the predicate's own voice (`doesNotAssert`,
the asserted/attested split) asks a verifier to say what it covers rather than
let a `pass` imply more than it checked. This file is that statement about
the verifier itself.

## Implemented and tested against self-authored fixtures

- **GATE 0 -- statement well-formedness**: `_type`/`predicateType`, subject
  cardinality and digest shape, `result` vocabulary, `issuedAt` profile
  (uppercase `T`/`Z`, zone `Z`/`+00:00`/`-00:00` only), the full
  `observationEnvironment` (substrate/catchPolicy digest shape, corpus
  manifest digest recompute, `expectedPayloads` shape, networkPosture closed
  vocabulary, observationVocabulary shape/subset/sort-order/BMP-only/digest
  recompute), `coverage` partition over the manifest's classes, attack-id
  uniqueness (within a row set and across classes), coverage integrity at
  attack granularity, per-row required members (`containmentObserved`,
  `basis`, `method`, `attribution`, `actualLayer`) present, `observationRefs`
  in-range, `runEntropy` required-when-substrate-row.
- Strict I-JSON parsing (own hand-rolled parser, `ijson_strict.py`): duplicate
  members at any depth, nesting bound of 128, unpaired surrogate escapes,
  raw control characters, Unicode noncharacters, the RFC 7493 safe-integer
  profile (`|int| < 2**53`), ill-formed UTF-8 at the byte level.
- `result` recompute as the byte-pure minimum of the three independent
  conditions (fail-closed row membership / disclosed coverage gap / indirect
  clean row), read only from required row members with closed vocabularies.
- **GATE 1 -- coverage validity (core)**: batchRoot recompute (RFC 6962,
  domain separated) checked against the carried `batchRoot`, run-binding
  derivation and the anti-splice equality on every covering record,
  per-`aeeKind` constraints for `interception`/`arming`/`sealed`/
  `examination`, class-match per row, the method cap by weakest covering
  `aeeMethod`, the clean-row/interception contradiction, the
  unresolved-interception requirement, and the sealed-record
  existence+`aeeObservedSet` requirement -- all enforced via real `require()`
  checks (`gate1.py`), invoked from `aee_verify.py`. A statement carrying
  `basis: substrate` rows is therefore checked at both GATE 0 and GATE 1
  today, not GATE 0 alone.

## Not implemented at this submission

- **GATE 1 -- a short list of finer joint checks**: the joint
  posture-equality check between a sealed record and every arming record a
  *specific row* resolves (as opposed to the pinned-digest equality, which
  is checked), `aeeDropBound` interaction, and the two
  `aeeAssessedAttacks`/`aeeObservedAttacks` edge cases beyond their basic
  subset/obligation rules. GATE 1's core, above, is implemented -- this is
  what remains deferred within it.
- **GATE 2 -- real evidence tier**: DSSE PAE verification against
  consumer-pinned Ed25519 keys is not implemented. `derive_tiers()` always
  returns `declared` for `basis: artifact` rows and `unattested` for
  `basis: substrate` rows, regardless of `AEE_SUBSTRATE_KEYS`. This is the
  sound direction to be incomplete in: it can only under-credit a row
  (toward the bottom of both consumer orderings), never fabricate an
  `attested` tier that did not verify.
- BMP-only enforcement is applied only where the spec requires it narrowly
  (`observationVocabulary.labels`/`caught`); it is not yet applied to
  covering-record payload member names (which requires parsing those
  payloads, part of GATE 1).
- The `aeeRunSeq`/`aeePrevRunBinding`/`aeeChainScope` cross-run chain members
  are not read (they are syntax-only within one statement and never alter
  `result`, the recompute or GATE 0/1 as implemented here, so omitting them
  changes no verdict on a single statement -- but a future version checking
  their syntax should still report that explicitly rather than silently).

## Why GATE 0 + recompute first

This was the plan approved before writing any code: GATE 0 and the
recompute are the two stages explicitly presented as byte-pure functions of
the carried statement alone, decidable with no key material and no
coverage-validity machinery, and they are also the pair the spec itself
separates most sharply from everything trust-relative. Coverage validity
(GATE 1) and the evidence tier (GATE 2) are real engineering, proportional
to the time actually available before the deadline, not skipped by
oversight.
