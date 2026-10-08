"""Self-authored GATE 1 fixtures: substrate-basis rows with real
arming/sealed/interception records, run binding and batchRoot all
computed by hand against this build's own understanding of the spec.
Nothing here is copied from or derived against agent-evidence-vectors'
shipped corpus.
"""
import base64
import hashlib
import json
import os

from jcs import jcs_bytes
from run_binding import derive_run_binding
from dsse_merkle import leaf_hash, rfc6962_root

FIX_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
os.makedirs(FIX_DIR, exist_ok=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_jcs_hex(obj) -> str:
    return sha256_hex(jcs_bytes(obj))


def canonical_record(payload_obj: dict, payload_type: str = "application/vnd.aee.test+json"):
    raw = jcs_bytes(payload_obj)
    return {
        "payload": base64.b64encode(raw).decode("ascii"),
        "payloadType": payload_type,
        "signatures": [{"keyid": "test-key-1", "sig": base64.b64encode(b"not-a-real-signature").decode("ascii")}],
    }, raw


def write(name, obj_or_bytes):
    path = os.path.join(FIX_DIR, name)
    if isinstance(obj_or_bytes, bytes):
        with open(path, "wb") as f:
            f.write(obj_or_bytes)
    else:
        with open(path, "w") as f:
            json.dump(obj_or_bytes, f)
    print("wrote", path)


MANIFEST = {"classes": {"CO": ["CO-EXFIL-1"]}}
LABELS = ["egress_captured", "no_egress"]
CAUGHT = ["egress_captured"]


def build_environment():
    # Deep-copy the manifest per call: later scenarios mutate their own
    # environment's manifest (e.g. adding expectedPayloads), and a shared
    # dict reference would silently corrupt earlier fixtures already built
    # from the same global MANIFEST object.
    manifest = json.loads(json.dumps(MANIFEST))
    vocab_digest = sha256_jcs_hex({"caught": CAUGHT, "labels": LABELS})
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
            "labels": LABELS,
            "caught": CAUGHT,
        },
        "runEntropy": {"digest": {"sha256": sha256_hex(b"run-entropy-1")}},
    }


def build_skeleton(result, coverage=None):
    env = build_environment()
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact", "digest": {"sha256": sha256_hex(b"artifact")}}],
        "predicateType": "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7",
        "predicate": {
            "result": result,
            "observationEnvironment": env,
            "coverage": coverage or {"assessedClasses": ["CO"], "outOfScope": {}, "routedElsewhere": {}},
            "attackResults": [],
            "observationRecords": [],
            "issuedAt": "2026-06-23T16:08:07Z",
        },
    }


def finalize(stmt, records_raw_payloads, row, attack_row_extra=None):
    """records_raw_payloads: list of (payload_obj, payload_type) in final order."""
    records = []
    leaves = []
    for payload_obj, payload_type in records_raw_payloads:
        rec, raw = canonical_record(payload_obj, payload_type)
        records.append(rec)
        leaves.append(leaf_hash(payload_type, raw))
    root = rfc6962_root(leaves)
    stmt["predicate"]["observationRecords"] = records
    stmt["predicate"]["batchRoot"] = root.hex()
    stmt["predicate"]["attackResults"] = [row]
    return stmt


def main():
    # --- clean row, live interception, pass -------------------------------
    stmt = build_skeleton("pass")
    run_binding = derive_run_binding(stmt, stmt["predicate"])

    arming = {
        "aeeRunBinding": run_binding,
        "aeeKind": "arming",
        "aeeMethod": "intercepted",
        "armedAt": "2026-06-23T16:00:00Z",
        "aeePostureDigest": stmt["predicate"]["observationEnvironment"]["networkPosture"]["digest"]["sha256"],
        "aeeAssessedAttacks": ["CO-EXFIL-1"],
    }
    sealed_payload_no_observed = {
        "aeeRunBinding": run_binding,
        "aeeKind": "sealed",
        "aeeMethod": "intercepted",
        "aeeStillArmed": True,
        "aeeDropCount": 0,
        "aeePostureDigest": stmt["predicate"]["observationEnvironment"]["networkPosture"]["digest"]["sha256"],
        "aeeObservedSet": None,  # placeholder, fixed below
        "aeeObservedAttacks": [],
    }
    # aeeObservedSet over interception+examination records -- none in this
    # fixture (the clean row has no per-event record by definition), so it
    # is the digest of the empty array.
    empty_observed_set = sha256_jcs_hex([])
    sealed_payload_no_observed["aeeObservedSet"] = empty_observed_set

    row = {
        "attackId": "CO-EXFIL-1",
        "containmentObserved": "no_egress",
        "basis": "substrate",
        "method": "intercepted",
        "attribution": "paired",
        "actualLayer": "none",
        "observationRefs": [0, 1],
    }
    finalize(
        stmt,
        [(arming, "application/vnd.aee.arming+json"), (sealed_payload_no_observed, "application/vnd.aee.sealed+json")],
        row,
    )
    write("ok-gate1-pass-clean-intercepted.json", stmt)

    # --- caught row, real interception, pinned attribution ---------------
    stmt2 = build_skeleton("fail")
    manifest2 = {"classes": {"CO": ["CO-EXFIL-1"]}}
    expected_payload_value = sha256_hex(b"expected-exfil-payload")
    stmt2["predicate"]["observationEnvironment"]["corpus"]["manifest"]["expectedPayloads"] = {
        "CO-EXFIL-1": [expected_payload_value]
    }
    stmt2["predicate"]["observationEnvironment"]["corpus"]["digest"]["sha256"] = sha256_jcs_hex(
        stmt2["predicate"]["observationEnvironment"]["corpus"]["manifest"]
    )
    run_binding2 = derive_run_binding(stmt2, stmt2["predicate"])

    interception = {
        "aeeRunBinding": run_binding2,
        "aeeKind": "interception",
        "aeeMethod": "intercepted",
        "aeePayloadCommitment": [expected_payload_value],
    }
    sealed2 = {
        "aeeRunBinding": run_binding2,
        "aeeKind": "sealed",
        "aeeMethod": "intercepted",
        "aeeStillArmed": True,
        "aeeDropCount": 0,
        "aeePostureDigest": stmt2["predicate"]["observationEnvironment"]["networkPosture"]["digest"]["sha256"],
        "aeeObservedSet": None,
        "aeeObservedAttacks": ["CO-EXFIL-1"],
    }
    interception_raw = jcs_bytes(interception)
    interception_leaf = leaf_hash("application/vnd.aee.interception+json", interception_raw)
    observed_set2 = sha256_jcs_hex([interception_leaf.hex()])
    sealed2["aeeObservedSet"] = observed_set2

    row2 = {
        "attackId": "CO-EXFIL-1",
        "containmentObserved": "egress_captured",
        "basis": "substrate",
        "method": "intercepted",
        "attribution": "pinned",
        "actualLayer": "policy.egress_sinkhole",
        "observationRefs": [0, 1],
    }
    finalize(
        stmt2,
        [
            (interception, "application/vnd.aee.interception+json"),
            (sealed2, "application/vnd.aee.sealed+json"),
        ],
        row2,
    )
    write("ok-gate1-fail-caught-pinned.json", stmt2)

    # --- malformed: batchRoot tampered ------------------------------------
    stmt3 = json.loads(json.dumps(stmt2))
    stmt3["predicate"]["batchRoot"] = "0" * 64
    write("bad-gate1-batchroot-mismatch.json", stmt3)

    # --- malformed: clean row pointing at an interception record ---------
    stmt4 = json.loads(json.dumps(stmt))
    stmt4["predicate"]["attackResults"][0]["containmentObserved"] = "no_egress"
    # swap refs so the clean row resolves record 0 which we relabel as an
    # interception by copying record content's semantics -- simplest way:
    # reuse ok-gate1-fail fixture's interception record appended here.
    extra_rec, extra_raw = canonical_record(interception, "application/vnd.aee.interception+json")
    # rebuild with a mismatched run binding scenario would be more complex;
    # instead directly test the contradiction by pointing the existing
    # clean row at index 0 (currently the local "arming" record) relabeled.
    bad_arming_as_interception = dict(arming)
    bad_arming_as_interception["aeeKind"] = "interception"
    bad_arming_as_interception["aeePayloadCommitment"] = [sha256_hex(b"x")]
    rec, raw = canonical_record(bad_arming_as_interception, "application/vnd.aee.interception+json")
    stmt4["predicate"]["observationRecords"][0] = rec
    leaves4 = [
        leaf_hash(r["payloadType"], base64.b64decode(r["payload"])) for r in stmt4["predicate"]["observationRecords"]
    ]
    stmt4["predicate"]["batchRoot"] = rfc6962_root(leaves4).hex()
    write("bad-gate1-clean-row-points-at-interception.json", stmt4)


if __name__ == "__main__":
    main()
