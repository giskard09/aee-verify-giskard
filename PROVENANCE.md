# Provenance

For astrogilda's Empirical Software Engineering study on independent spec
builders (a2aproject/a2a-tck#228, comment 6048985871, invitation at
https://github.com/probityai/agent-evidence-vectors/blob/study/emse-2026-invitations/docs/study/emse-2026/builders.md).

## Tools and model

Written with Claude Code (Anthropic), model Claude Sonnet 5, acting as
"Giskard" for Rama/Mycelium (github.com/giskard09). A coding agent wrote
this code; a human (the repository's operator) reviewed and approved it
before it was posted.

## Prior exposure (declared per builders.md)

> "Please don't look at my test set, its changelog or the two existing
> verifiers before you post your build. If you already have, you're
> still welcome. Just tell me, and I'll report your build in a group of
> its own."

On 2026-09-17, for an unrelated task (packaging two conformance vectors
for a different standards thread, finos/ai-governance-framework#337), we
installed `agent-evidence-vectors` and read the full source of its
`run_vectors.py` and `MANIFEST.json` at that time's installed version. We
did not know this invitation would exist when that happened.

What we recovered from that exposure, to the best of our own account: the
AEE predicate's four-gate structure, several field names already present
verbatim in the normative spec text (`aeeKind`, `aeeMethod`,
`aeeAssessedAttacks`, `batchRoot`/RFC 6962, the evidence-tier concept), and
the fact that the shipped CLI derives test substrate keys from a fixed
seed. We did not re-read that source during this build, and this build's
own code was written solely against the pinned spec text and the publicly
documented external-verifier CLI contract (the "What the suite compares"
section of the pinned 0.12.1 PyPI README). We never looked at
`vectors/accept`, `vectors/reject`, or either of the two other builders'
code, at any point.

We are telling you this rather than omitting it, per the quoted term
above, and leave it to you whether this build is reported in the blind
group or in a group of its own.

## What was read to build this

- The pinned spec (SHA-256 `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`),
  read in full before any code was written.
- `docs/reference/verifier-contract.md` (the published external-verifier
  CLI contract) and the "What the suite compares" section of the pinned
  0.12.1 PyPI README -- both explicitly pointed to by builders.md as the
  output-format reference, not part of the vedated test-set/changelog/
  verifier material.
- Our own prior work, `jcs.py` (RFC 8785 canonicalization), vendored
  unchanged from `giskard09/argentum-core`.

## Commit and command

See the commit this PROVENANCE.md ships with for the exact commit SHA.
Run: `python3 aee_verify.py <statement.json>`.
