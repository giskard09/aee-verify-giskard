"""Run binding digest (aeeBindingVersion: 2), per the predicate's
"Prerequisites" / "Run binding" section.
"""
from __future__ import annotations

import hashlib

from jcs import jcs_bytes


def sha256_jcs_hex(obj) -> str:
    return hashlib.sha256(jcs_bytes(obj)).hexdigest()


def derive_run_binding(statement: dict, predicate: dict) -> str:
    env = predicate["observationEnvironment"]
    posture_digest = sha256_jcs_hex(env["networkPosture"])
    pre_image = {
        "aeeBindingVersion": "2",
        "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
        "corpus": env["corpus"]["digest"]["sha256"],
        "networkPosture": posture_digest,
        "observationVocabulary": env["observationVocabulary"]["digest"]["sha256"],
        "runEntropy": env["runEntropy"]["digest"]["sha256"],
        "subject": statement["subject"][0]["digest"]["sha256"],
        "substrate": env["substrate"]["digest"]["sha256"],
    }
    return sha256_jcs_hex(pre_image)
