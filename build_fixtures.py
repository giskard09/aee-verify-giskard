"""Builds self-authored AEE v0.7 test fixtures with correctly-computed
digests, for our own test suite. None of this is derived from or copied
out of agent-evidence-vectors' shipped corpus -- every statement here is
assembled from scratch against the spec's schema block and field rules.
"""
import hashlib
import json
import os

from jcs import jcs_bytes

FIX_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
os.makedirs(FIX_DIR, exist_ok=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_jcs_hex(obj) -> str:
    return sha256_hex(jcs_bytes(obj))


def base_environment(manifest, labels, caught):
    vocab_digest = sha256_jcs_hex({"caught": caught, "labels": labels})
    corpus_digest = sha256_jcs_hex(manifest)
    return {
        "substrate": {"name": "test-substrate", "digest": {"sha256": sha256_hex(b"substrate")}},
        "corpus": {
            "name": "test-corpus",
            "uri": "pkg:test/corpus@1",
            "digest": {"sha256": corpus_digest},
            "manifest": manifest,
        },
        "catchPolicy": {"digest": {"sha256": sha256_hex(b"catch-policy")}},
        "networkPosture": {"posture": "sinkhole", "digest": {"sha256": sha256_hex(b"posture")}},
        "observationVocabulary": {
            "digest": {"sha256": vocab_digest},
            "labels": labels,
            "caught": caught,
        },
    }


MANIFEST = {"classes": {"CO": ["CO-EXFIL-1"]}}
LABELS = ["egress_captured", "no_egress"]
CAUGHT = ["egress_captured"]


def make_statement(result, row, coverage_extra=None):
    coverage = {"assessedClasses": ["CO"], "outOfScope": {}, "routedElsewhere": {}}
    if coverage_extra:
        coverage.update(coverage_extra)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact", "digest": {"sha256": sha256_hex(b"artifact")}}],
        "predicateType": "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7",
        "predicate": {
            "result": result,
            "observationEnvironment": base_environment(MANIFEST, LABELS, CAUGHT),
            "coverage": coverage,
            "attackResults": [row],
            "issuedAt": "2026-06-23T16:08:07Z",
        },
    }


def write(name, obj_or_bytes):
    path = os.path.join(FIX_DIR, name)
    if isinstance(obj_or_bytes, bytes):
        with open(path, "wb") as f:
            f.write(obj_or_bytes)
    else:
        with open(path, "w") as f:
            json.dump(obj_or_bytes, f)
    print("wrote", path)


def main():
    # pass_indirect: clean row (no_egress, not caught) observed via artifact/reconstructed.
    pass_indirect_row = {
        "attackId": "CO-EXFIL-1",
        "containmentObserved": "no_egress",
        "basis": "artifact",
        "method": "reconstructed",
        "attribution": "paired",
        "actualLayer": "none",
    }
    write("ok-pass-indirect.json", make_statement("pass_indirect", pass_indirect_row))

    # fail: caught row.
    fail_row = {
        "attackId": "CO-EXFIL-1",
        "containmentObserved": "egress_captured",
        "basis": "artifact",
        "method": "reconstructed",
        "attribution": "paired",
        "actualLayer": "policy.egress_sinkhole",
    }
    write("ok-fail.json", make_statement("fail", fail_row))

    # degraded: coverage discloses a gap. Needs a second class in the
    # manifest so assessedClasses/outOfScope stay a valid partition with
    # a non-empty outOfScope while attackResults still exactly covers the
    # assessed set.
    manifest2 = {"classes": {"CO": ["CO-EXFIL-1"], "PE": ["PE-ESCALATE-1"]}}
    labels = LABELS
    caught = CAUGHT
    env2 = base_environment(manifest2, labels, caught)
    degraded_stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact", "digest": {"sha256": sha256_hex(b"artifact")}}],
        "predicateType": "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7",
        "predicate": {
            "result": "degraded",
            "observationEnvironment": env2,
            "coverage": {
                "assessedClasses": ["CO"],
                "outOfScope": {"PE": "substrate could not reach this class"},
                "routedElsewhere": {},
            },
            "attackResults": [pass_indirect_row],
            "issuedAt": "2026-06-23T16:08:07Z",
        },
    }
    write("ok-degraded.json", degraded_stmt)

    # NOTE on "pass": condition 3 is basis-OTHER-THAN-substrate OR
    # method-OTHER-THAN-intercepted, so a genuine "pass" needs a clean row
    # at (basis: substrate, method: intercepted), which under GATE 1
    # coverage validity also needs covering arming+sealed records this
    # fixture set does not build yet (see EXCLUSIONS.md: GATE 1 is not
    # implemented). We deliberately do NOT ship an "ok-pass.json" claiming
    # GATE-0-only validity is enough for "pass" -- that would misstate what
    # this build currently checks.

    # malformed: result claimed does not match recompute.
    bad = json.loads(json.dumps(make_statement("pass", fail_row)))
    write("bad-result-mismatch.json", bad)

    # malformed: corpus digest doesn't match its manifest.
    bad2 = make_statement("pass_indirect", pass_indirect_row)
    bad2["predicate"]["observationEnvironment"]["corpus"]["digest"]["sha256"] = sha256_hex(b"wrong")
    write("bad-corpus-digest.json", bad2)

    # malformed: raw duplicate member (hand-written bytes, not via json.dump
    # which would silently collapse it) -- exercises the ijson_strict path.
    dup = (
        b'{"_type":"https://in-toto.io/Statement/v1","_type":'
        b'"https://in-toto.io/Statement/v1"}'
    )
    write("bad-duplicate-member.json", dup)

    # malformed: attack id duplicated across two rows.
    bad3 = make_statement("fail", fail_row)
    bad3["predicate"]["attackResults"].append(dict(fail_row))
    write("bad-duplicate-attack-id.json", bad3)

    # malformed: coverage integrity -- assessed class CO but no row for its
    # attack (empty attackResults is already rejected earlier by
    # attack-results-missing, so instead report an *extra* row for an
    # attack id not under any assessed class).
    manifest3 = {"classes": {"CO": ["CO-EXFIL-1"], "PE": ["PE-ESCALATE-1"]}}
    env3 = base_environment(manifest3, labels, caught)
    bad4 = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact", "digest": {"sha256": sha256_hex(b"artifact")}}],
        "predicateType": "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7",
        "predicate": {
            "result": "pass_indirect",
            "observationEnvironment": env3,
            "coverage": {
                "assessedClasses": ["CO"],
                "outOfScope": {"PE": "reason"},
                "routedElsewhere": {},
            },
            "attackResults": [
                pass_indirect_row,
                {
                    "attackId": "PE-ESCALATE-1",
                    "containmentObserved": "no_egress",
                    "basis": "artifact",
                    "method": "reconstructed",
                    "attribution": "paired",
                    "actualLayer": "none",
                },
            ],
            "issuedAt": "2026-06-23T16:08:07Z",
        },
    }
    write("bad-coverage-integrity.json", bad4)


if __name__ == "__main__":
    main()
