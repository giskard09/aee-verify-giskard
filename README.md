# aee-verify-giskard

An independent verifier for the in-toto **Adversarial Execution Evidence**
predicate (`predicateType: https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`),
built from the spec text alone for astrogilda's Empirical Software
Engineering study on independent spec builders
(a2aproject/a2a-tck#228, comment 6048985871).

Pinned spec: https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.12.1/spec/predicates/adversarial-execution-evidence.md
SHA-256: `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`

## Run it

```
python3 aee_verify.py <statement.json>
```

Prints one JSON object on the last stdout line:
`{"verdict": "valid"|"invalid", "codes": [...], "result": ..., "tiers": [...]}`.
Exit status 0 iff valid, nonzero iff invalid. `AEE_SUBSTRATE_KEYS`, if set,
should name a `{"substrateObservationKeys": [...]}` key-policy file (see
EXCLUSIONS.md for what this build currently does with it: nothing yet --
every `basis: substrate` row is reported `unattested` regardless).

## What this checks, and what it does not

See [EXCLUSIONS.md](EXCLUSIONS.md). GATE 0 (statement well-formedness) and
the `result` recompute are complete and tested. GATE 1 (coverage validity)
covers batchRoot/run-binding/class-match/method-cap/the sealed-existence
requirement; a short list of finer joint checks is explicitly deferred.
GATE 2 (real DSSE/Ed25519 signature verification) is out of scope at this
submission by design -- see the note there on why that is the sound
direction to be incomplete in.

## Disclosure

Required by [builders.md](https://github.com/probityai/agent-evidence-vectors/blob/study/emse-2026-invitations/docs/study/emse-2026/builders.md):
see [PROVENANCE.md](PROVENANCE.md).

## Tests

```
python3 test_ijson_strict.py      # 19 cases, strict I-JSON parser
python3 build_fixtures.py         # (re)generates fixtures/*.json
python3 build_fixtures_gate1.py   # (re)generates GATE-1 fixtures
for f in fixtures/*.json; do python3 aee_verify.py "$f"; done
```

Every fixture is hand-authored against the spec's own schema and field
rules -- none of it is copied from, or derived against,
agent-evidence-vectors' shipped `vectors/accept` or `vectors/reject`
corpus.

## Layout

| File | Purpose |
| --- | --- |
| `ijson_strict.py` | Hand-rolled strict I-JSON (RFC 7493) parser the stdlib `json` module does not provide (duplicate-member rejection, nesting bound, surrogate/noncharacter checks, safe-integer profile) |
| `jcs.py` | RFC 8785 JSON canonicalization (vendored from `giskard09/argentum-core`, our own prior work, used elsewhere in production) |
| `common.py` | Shared helpers between GATE 0 and GATE 1 |
| `aee_verify.py` | CLI entrypoint, GATE 0 checks, `result` recompute, tier derivation |
| `gate1.py` | Coverage validity (GATE 1) |
| `dsse_merkle.py` | DSSE PAE encoding + RFC 6962 domain-separated Merkle tree |
| `run_binding.py` | The `aeeBindingVersion: 2` run-binding digest |

Apache-2.0, matching the rest of the `giskard09` worked-example series.
