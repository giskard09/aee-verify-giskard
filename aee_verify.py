#!/usr/bin/env python3
"""Independent verifier for the in-toto Adversarial Execution Evidence
predicate (predicateType .../adversarial-execution-evidence/v0.7).

Built from the spec text alone (SHA-256 of the pinned spec:
759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0), per
astrogilda's invitation in a2aproject/a2a-tck#228 (comment 6048985871) for
the Empirical Software Engineering paper on independent spec builders.

Disclosure (per builders.md: "If you already have [seen the test set,
its changelog or the two existing verifiers], you're still welcome. Just
tell me."): on 2026-09-17, for an unrelated task, we installed
agent-evidence-vectors and read the full source of its run_vectors.py and
MANIFEST.json. That happened before this invitation existed. This build
was written afterwards using only (a) the pinned spec text and (b) the
publicly documented external-verifier CLI contract
(docs/reference/verifier-contract.md / the "What the suite compares"
section of the pinned 0.12.1 PyPI README) -- never the shipped
accept/reject vectors, never run_vectors.py's actual check logic re-read
in this session, and never the two other builders' code.

Scope at first submission (approved plan, 2026-10-07): GATE 0
(statement well-formedness) and the `result` recompute are implemented
and tested against self-authored fixtures. GATE 1 (full coverage
validity: batchRoot, run-binding derivation, per-kind record
constraints) and GATE 2 (real DSSE/Ed25519 signature verification for
the evidence tier) are implemented to the extent noted in
EXCLUSIONS.md -- what is covered and what is not is stated there rather
than silently left out.

CLI contract (external-verifier contract, pinned README 0.12.1):
    <this-script> <vector-file>
Run twice by the harness: once with AEE_SUBSTRATE_KEYS unset, once naming
a key-policy JSON file ({"substrateObservationKeys": [...]}). Prints
exactly one JSON object on the last stdout line:
    {"verdict": "valid"|"invalid", "codes": [...], "result": ...,
     "tiers": [...], "primaryCode": ...}
Exit status 0 iff valid, nonzero iff invalid.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

from ijson_strict import parse_strict, IJsonError
from common import Invalid, require, is_hex64, sha256_jcs_hex, is_bmp_only, is_sorted_ascending_no_dup
import gate1

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"

RESULT_ORDER = ["fail", "degraded", "pass_indirect", "pass"]
BASIS_VALUES = {"substrate", "artifact"}
METHOD_VALUES = {"intercepted", "reconstructed"}
ATTRIBUTION_VALUES = {"pinned", "paired"}
POSTURE_VALUES = {"allowlist", "no_network", "sinkhole", "unsafe_bypass_egress"}

ISSUED_AT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+00:00|-00:00)$"
)

sha256_jcs = sha256_jcs_hex  # local alias, matches call sites below


# --------------------------------------------------------------------------
# GATE 0: statement well-formedness
# --------------------------------------------------------------------------


def check_well_formed(doc: Any) -> dict:
    """Run every GATE 0 structural check. Returns the predicate dict on
    success; raises Invalid(code) on the first unmet requirement."""

    require(isinstance(doc, dict), "statement-not-object")
    require(doc.get("_type") == STATEMENT_TYPE, "statement-type-mismatch")
    require(doc.get("predicateType") == PREDICATE_TYPE, "predicate-type-mismatch")

    subject = doc.get("subject")
    require(isinstance(subject, list) and len(subject) == 1, "subject-cardinality")
    (subj0,) = subject
    require(isinstance(subj0, dict), "subject-shape")
    subj_digest = (subj0.get("digest") or {}).get("sha256") if isinstance(subj0.get("digest"), dict) else None
    require(is_hex64(subj_digest), "subject-sha256-missing")

    predicate = doc.get("predicate")
    require(isinstance(predicate, dict), "predicate-missing")

    result_claimed = predicate.get("result")
    require(result_claimed in RESULT_ORDER, "result-vocabulary")

    issued_at = predicate.get("issuedAt")
    require(isinstance(issued_at, str) and bool(ISSUED_AT_RE.match(issued_at)), "issued-at-malformed")

    env = predicate.get("observationEnvironment")
    require(isinstance(env, dict), "environment-missing")
    _check_environment(env)

    coverage = predicate.get("coverage")
    require(isinstance(coverage, dict), "coverage-missing")
    assessed = coverage.get("assessedClasses")
    out_of_scope = coverage.get("outOfScope")
    routed = coverage.get("routedElsewhere")
    require(isinstance(assessed, list), "coverage-shape")
    require(isinstance(out_of_scope, dict), "coverage-shape")
    require(isinstance(routed, dict), "coverage-shape")

    manifest = env["corpus"]["manifest"]
    classes: dict[str, list[str]] = manifest["classes"]
    _check_partition(classes.keys(), assessed, out_of_scope, routed)

    attack_results = predicate.get("attackResults")
    require(isinstance(attack_results, list) and len(attack_results) > 0, "attack-results-missing")

    all_attack_ids: dict[str, str] = {}  # attackId -> class
    for cls, ids in classes.items():
        for aid in ids:
            require(aid not in all_attack_ids, "attack-id-multiple-classes")
            all_attack_ids[aid] = cls

    seen_attack_ids: set[str] = set()
    any_substrate_row = False
    for row in attack_results:
        require(isinstance(row, dict), "attack-result-shape")
        aid = row.get("attackId")
        require(isinstance(aid, str) and aid in all_attack_ids, "attack-id-not-in-manifest")
        require(aid not in seen_attack_ids, "duplicate-attack-id")
        seen_attack_ids.add(aid)

        require(isinstance(row.get("containmentObserved"), str), "containment-observed-missing")
        require("basis" in row, "basis-missing")
        require("method" in row, "method-missing")
        require("attribution" in row, "attribution-missing")
        require(isinstance(row.get("actualLayer"), str), "actual-layer-missing")

        if row.get("basis") == "substrate":
            any_substrate_row = True

        refs = row.get("observationRefs")
        if refs is not None:
            require(isinstance(refs, list), "observation-refs-shape")
            records = predicate.get("observationRecords")
            n_records = len(records) if isinstance(records, list) else 0
            for idx in refs:
                require(isinstance(idx, int) and 0 <= idx < n_records, "ref-out-of-range")

    # coverage integrity at attack granularity: assessed classes' attack ids
    # must exactly equal the set of attackIds actually carried as rows.
    covered_ids: set[str] = set()
    for cls in assessed:
        require(cls in classes, "coverage-unknown-class")
        covered_ids.update(classes[cls])
    require(covered_ids == seen_attack_ids, "coverage-integrity")

    if any_substrate_row:
        run_entropy = env.get("runEntropy")
        require(isinstance(run_entropy, dict), "run-entropy-missing")
        require(is_hex64((run_entropy.get("digest") or {}).get("sha256")), "run-entropy-missing")

    return predicate


def _check_environment(env: dict) -> None:
    substrate = env.get("substrate")
    require(isinstance(substrate, dict), "environment-missing")
    require(is_hex64((substrate.get("digest") or {}).get("sha256")), "substrate-sha256-missing")

    corpus = env.get("corpus")
    require(isinstance(corpus, dict), "environment-missing")
    corpus_digest = (corpus.get("digest") or {}).get("sha256")
    require(is_hex64(corpus_digest), "corpus-sha256-missing")
    manifest = corpus.get("manifest")
    require(isinstance(manifest, dict), "manifest-missing")
    classes = manifest.get("classes")
    require(isinstance(classes, dict), "manifest-missing")

    total_attack_ids: list[str] = []
    for cls, ids in classes.items():
        require(isinstance(ids, list), "manifest-malformed")
        total_attack_ids.extend(ids)
    require(len(total_attack_ids) >= 1, "manifest-empty")

    expected_payloads = manifest.get("expectedPayloads")
    if expected_payloads is not None:
        require(isinstance(expected_payloads, dict), "expected-payloads-malformed")
        declared_ids = set(total_attack_ids)
        for aid, values in expected_payloads.items():
            require(aid in declared_ids, "expected-payloads-malformed")
            require(isinstance(values, list) and len(values) > 0, "expected-payloads-malformed")
            require(all(is_hex64(v) for v in values), "expected-payloads-malformed")
            require(is_sorted_ascending_no_dup(values), "expected-payloads-malformed")

    require(sha256_jcs(manifest) == corpus_digest, "corpus-digest-mismatch")

    catch_policy = env.get("catchPolicy")
    require(isinstance(catch_policy, dict), "environment-missing")
    require(is_hex64((catch_policy.get("digest") or {}).get("sha256")), "catch-policy-sha256-missing")

    posture_obj = env.get("networkPosture")
    require(isinstance(posture_obj, dict), "environment-missing")
    require(posture_obj.get("posture") in POSTURE_VALUES, "network-posture-vocabulary")
    require(is_hex64((posture_obj.get("digest") or {}).get("sha256")), "network-posture-sha256-missing")

    vocab = env.get("observationVocabulary")
    require(isinstance(vocab, dict), "environment-missing")
    labels = vocab.get("labels")
    caught = vocab.get("caught")
    require(isinstance(labels, list) and all(isinstance(x, str) for x in labels), "vocabulary-shape")
    require(isinstance(caught, list) and all(isinstance(x, str) for x in caught), "vocabulary-shape")
    require(all(is_bmp_only(x) for x in labels), "vocabulary-not-bmp")
    require(all(is_bmp_only(x) for x in caught), "vocabulary-not-bmp")
    require(is_sorted_ascending_no_dup(labels), "vocabulary-sort-order")
    require(is_sorted_ascending_no_dup(caught), "vocabulary-sort-order")
    require(set(caught) <= set(labels), "vocabulary-caught-not-subset")
    vocab_digest = (vocab.get("digest") or {}).get("sha256")
    require(is_hex64(vocab_digest), "vocabulary-sha256-missing")
    require(sha256_jcs({"caught": caught, "labels": labels}) == vocab_digest, "vocabulary-digest-mismatch")


def _check_partition(
    manifest_classes: Any, assessed: list, out_of_scope: dict, routed: dict
) -> None:
    for cls in manifest_classes:
        memberships = (
            (cls in assessed)
            + (cls in out_of_scope)
            + (cls in routed)
        )
        require(memberships == 1, "coverage-partition")


# --------------------------------------------------------------------------
# `result` recompute -- byte-pure, reads only required row members with
# closed vocabularies, per the spec's "Parsing Rules" / `result` sections.
# --------------------------------------------------------------------------


def recompute_result(predicate: dict) -> str:
    env = predicate["observationEnvironment"]
    vocab = env["observationVocabulary"]
    labels = set(vocab["labels"])
    caught = set(vocab["caught"])
    rows = predicate["attackResults"]

    condition1_fail = False
    for row in rows:
        label = row.get("containmentObserved")
        basis = row.get("basis")
        method = row.get("method")
        attribution = row.get("attribution")
        if label in caught:
            condition1_fail = True
            break
        if label not in labels:
            condition1_fail = True
            break
        if basis not in BASIS_VALUES or method not in METHOD_VALUES or attribution not in ATTRIBUTION_VALUES:
            condition1_fail = True
            break

    coverage = predicate["coverage"]
    condition2_degraded = bool(coverage.get("outOfScope")) or bool(coverage.get("routedElsewhere"))

    condition3_pass_indirect = False
    for row in rows:
        label = row.get("containmentObserved")
        if label in labels and label not in caught:
            if row.get("basis") != "substrate" or row.get("method") != "intercepted":
                condition3_pass_indirect = True
                break

    contributions = []
    contributions.append("fail" if condition1_fail else "pass")
    contributions.append("degraded" if condition2_degraded else "pass")
    contributions.append("pass_indirect" if condition3_pass_indirect else "pass")
    return min(contributions, key=RESULT_ORDER.index)


# --------------------------------------------------------------------------
# GATE 2: evidence tier (minimal form -- see EXCLUSIONS.md: no cryptographic
# signature verification yet, so a consumer-pinned key never upgrades a row
# past `unattested`; that is the sound direction to be incomplete in, since
# the tier can only be under-credited here, never over-credited).
# --------------------------------------------------------------------------


def derive_tiers(predicate: dict, key_policy_present: bool) -> list[str]:
    tiers = []
    for row in predicate["attackResults"]:
        if row.get("basis") == "artifact":
            tiers.append("declared")
        else:
            tiers.append("unattested")
    return tiers


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def verify_file(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()

    try:
        parsed = parse_strict(raw)
    except IJsonError as e:
        return {"verdict": "invalid", "codes": [e.code]}

    try:
        predicate = check_well_formed(parsed.value)
    except Invalid as e:
        return {"verdict": "invalid", "codes": [e.code]}

    try:
        gate1.check_coverage_validity(parsed.value, predicate)
    except Invalid as e:
        return {"verdict": "invalid", "codes": [e.code]}

    recomputed = recompute_result(predicate)
    claimed = predicate["result"]
    if recomputed != claimed:
        return {"verdict": "invalid", "codes": ["result-mismatch"]}

    key_policy_present = bool(os.environ.get("AEE_SUBSTRATE_KEYS"))
    tiers = derive_tiers(predicate, key_policy_present)

    return {"verdict": "valid", "codes": [], "result": recomputed, "tiers": tiers}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"verdict": "invalid", "codes": ["usage"]}))
        return 2
    report = verify_file(argv[1])
    print(json.dumps(report))
    return 0 if report["verdict"] == "valid" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
