"""GATE 1: coverage validity.

Implements the structural, byte-pure record-level requirements under
"Coverage validity" in the spec: batchRoot recompute (RFC 6962, domain
separated), run-binding derivability and the anti-splice equality on every
covering record, per-`aeeKind` constraints, class-match per row, the
method cap by weakest covering `aeeMethod`, the clean-row/interception
contradiction, the unresolved-interception requirement, and the
sealed-record existence+`aeeObservedSet` requirement.

See EXCLUSIONS.md for what is intentionally simplified here: the joint
posture-equality check between a sealed record and every arming record a
*specific row* resolves (as opposed to the pinned-digest equality, which
is checked), `aeeDropBound` interaction, and the two
`aeeAssessedAttacks`/`aeeObservedAttacks` edge cases beyond their basic
subset/obligation rules.
"""
from __future__ import annotations

import base64

from common import Invalid, require, is_hex64, is_sorted_ascending_no_dup
from ijson_strict import parse_strict, IJsonError
from jcs import jcs_bytes
from run_binding import derive_run_binding
from dsse_merkle import leaf_hash, rfc6962_root

COVERING_KINDS = {"interception", "arming", "sealed", "examination"}
NON_COVERING_KINDS = {"moat-drop", "uncommitted-observation"}


class _Record:
    __slots__ = ("raw_payload", "payload_type", "leaf", "obj", "kind", "valid")

    def __init__(self, raw_payload: bytes, payload_type: str, leaf: bytes):
        self.raw_payload = raw_payload
        self.payload_type = payload_type
        self.leaf = leaf
        self.obj: dict | None = None
        self.kind: str | None = None
        self.valid = False  # "satisfies every constraint of its declared kind"


def _parse_canonical_payload(raw_payload: bytes) -> dict | None:
    try:
        parsed = parse_strict(raw_payload)
    except IJsonError:
        return None
    obj = parsed.value
    if not isinstance(obj, dict):
        return None
    if jcs_bytes(obj) != raw_payload:
        return None  # not canonical RFC 8785 -- "covers nothing"
    return obj


def _validate_kind(
    rec_obj: dict, run_binding: str, manifest_attack_ids: set[str],
    assessed_union: set[str],
) -> bool:
    if rec_obj.get("aeeRunBinding") != run_binding:
        return False
    kind = rec_obj.get("aeeKind")
    method = rec_obj.get("aeeMethod")

    if kind == "interception":
        commitments = rec_obj.get("aeePayloadCommitment")
        if not (isinstance(commitments, list) and len(commitments) > 0):
            return False
        if not all(is_hex64(c) for c in commitments):
            return False
        if not is_sorted_ascending_no_dup(commitments):
            return False
        return True

    if kind == "arming":
        if method != "intercepted":
            return False
        if not isinstance(rec_obj.get("armedAt"), str):
            return False
        assessed = rec_obj.get("aeeAssessedAttacks")
        if not (isinstance(assessed, list) and all(isinstance(a, str) for a in assessed)):
            return False
        if not is_sorted_ascending_no_dup(assessed):
            return False
        if not set(assessed) <= manifest_attack_ids:
            return False
        if not assessed_union <= set(assessed):
            return False
        if "aeePostureDigest" not in rec_obj:
            return False
        return True

    if kind == "sealed":
        if method != "intercepted":
            return False
        if not isinstance(rec_obj.get("aeeStillArmed"), bool):
            return False
        if not isinstance(rec_obj.get("aeeDropCount"), int) or isinstance(rec_obj.get("aeeDropCount"), bool):
            return False
        if "aeePostureDigest" not in rec_obj:
            return False
        if not is_hex64(rec_obj.get("aeeObservedSet")):
            return False
        observed_attacks = rec_obj.get("aeeObservedAttacks")
        if not (isinstance(observed_attacks, list) and all(isinstance(a, str) for a in observed_attacks)):
            return False
        if not is_sorted_ascending_no_dup(observed_attacks):
            return False
        if not set(observed_attacks) <= manifest_attack_ids:
            return False
        return True

    if kind == "examination":
        return method == "reconstructed"

    # unrecognized or non-covering kind: covers nothing, not itself an error.
    return False


def check_coverage_validity(statement: dict, predicate: dict) -> None:
    rows = predicate["attackResults"]
    any_substrate = any(r.get("basis") == "substrate" for r in rows)
    records_raw = predicate.get("observationRecords")

    if not any_substrate:
        return  # "a statement whose rows are all basis: artifact derives no binding"

    require(isinstance(records_raw, list) and len(records_raw) > 0, "records-absent")

    manifest = predicate["observationEnvironment"]["corpus"]["manifest"]
    manifest_attack_ids: set[str] = set()
    for ids in manifest["classes"].values():
        manifest_attack_ids.update(ids)
    assessed_union: set[str] = set()
    for cls in predicate["coverage"]["assessedClasses"]:
        assessed_union.update(manifest["classes"].get(cls, []))

    run_binding = derive_run_binding(statement, predicate)

    records: list[_Record] = []
    seen_leaves: set[bytes] = set()
    for rec in records_raw:
        require(isinstance(rec, dict), "observation-record-shape")
        sigs = rec.get("signatures")
        require(isinstance(sigs, list) and len(sigs) > 0, "record-signatures-empty")

        payload_b64 = rec.get("payload")
        payload_type = rec.get("payloadType")
        require(isinstance(payload_b64, str), "record-payload-shape")
        require(isinstance(payload_type, str) and payload_type.endswith("+json"), "record-media-type")
        try:
            raw_payload = base64.b64decode(payload_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise Invalid("record-payload-not-base64") from exc

        leaf = leaf_hash(payload_type, raw_payload)
        require(leaf not in seen_leaves, "duplicate-record")
        seen_leaves.add(leaf)

        r = _Record(raw_payload, payload_type, leaf)
        obj = _parse_canonical_payload(raw_payload)
        if obj is not None:
            r.obj = obj
            r.kind = obj.get("aeeKind")
            if r.kind in COVERING_KINDS:
                r.valid = _validate_kind(obj, run_binding, manifest_attack_ids, assessed_union)
        records.append(r)

    # batchRoot
    root = rfc6962_root([r.leaf for r in records])
    carried_root = predicate.get("batchRoot")
    require(isinstance(carried_root, str) and root is not None and carried_root == root.hex(), "batch-root-mismatch")

    # aeeObservedSet: over every carried interception/examination record,
    # regardless of per-record validity (the member is read off the
    # payload, which only requires the payload to parse canonically).
    io_hexes = sorted(
        {
            r.leaf.hex()
            for r in records
            if r.obj is not None and r.obj.get("aeeKind") in ("interception", "examination")
        }
    )
    observed_set_digest = None
    if io_hexes or any(r.kind == "sealed" for r in records):
        import hashlib

        observed_set_digest = hashlib.sha256(jcs_bytes(io_hexes)).hexdigest()

    sealed_ok_present = False
    for r in records:
        if r.kind == "sealed" and r.valid:
            if r.obj.get("aeeObservedSet") != observed_set_digest:
                r.valid = False
                continue
            observed_attacks = r.obj.get("aeeObservedAttacks")
            caught_set = set(predicate["observationEnvironment"]["observationVocabulary"]["caught"])
            row_by_attack = {row["attackId"]: row for row in rows}
            ok = True
            for aid in observed_attacks:
                row = row_by_attack.get(aid)
                if row is None or row.get("containmentObserved") not in caught_set:
                    ok = False
                    break
            if not ok:
                r.valid = False
                continue
            sealed_ok_present = True

    require(sealed_ok_present, "sealed-record-missing-or-invalid")

    # every carried record of a covering kind must satisfy its own
    # constraints regardless of whether any row resolves it (checked
    # above via r.valid at parse time for arming/sealed/examination/
    # interception already -- nothing further needed here, but a record
    # whose declared kind IS covering and is NOT valid must still be
    # distinguishable from one that simply covers nothing by being
    # unrecognized; both are handled identically below since neither can
    # be resolved into coverage).

    n_records = len(records)
    vocab = predicate["observationEnvironment"]["observationVocabulary"]
    caught_set = set(vocab["caught"])
    labels_set = set(vocab["labels"])
    resolved_idx: set[int] = set()

    for row in rows:
        if row.get("basis") != "substrate":
            continue
        refs = row.get("observationRefs") or []
        require(len(refs) > 0, "observation-refs-empty")
        for idx in refs:
            resolved_idx.add(idx)
        covering = [records[i] for i in refs if 0 <= i < n_records and records[i].valid]

        label = row.get("containmentObserved")
        is_caught = label in caught_set
        is_clean = (label in labels_set) and not is_caught
        method = row.get("method")

        if is_clean:
            require(
                not any(r.kind == "interception" for r in covering),
                "clean-row-points-at-interception",
            )

        if is_caught and method == "intercepted":
            require(any(r.kind == "interception" for r in covering), "class-match-interception-missing")
        elif method == "reconstructed":
            require(any(r.kind == "examination" for r in covering), "class-match-examination-missing")
        elif is_clean and method == "intercepted":
            require(any(r.kind == "arming" for r in covering), "class-match-arming-missing")
            require(any(r.kind == "sealed" for r in covering), "class-match-sealed-missing")

        if any(r.kind in COVERING_KINDS and r.obj.get("aeeMethod") == "reconstructed" for r in covering):
            require(method == "reconstructed", "method-cap-violation")

        if row.get("attribution") == "pinned":
            expected_payloads = (
                predicate["observationEnvironment"]["corpus"]["manifest"].get("expectedPayloads") or {}
            )
            expected_for_attack = set(expected_payloads.get(row["attackId"], []))
            require(
                any(
                    r.kind == "interception"
                    and set(r.obj.get("aeePayloadCommitment", [])) & expected_for_attack
                    for r in covering
                ),
                "attribution-pinned-unsupported",
            )

    for i, r in enumerate(records):
        if r.kind == "interception" and r.valid:
            require(i in resolved_idx, "unresolved-interception-record")
