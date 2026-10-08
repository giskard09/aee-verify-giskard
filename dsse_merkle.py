"""DSSE PAE encoding and the RFC 6962 domain-separated Merkle tree the AEE
predicate pins `batchRoot` and `aeeObservedSet` to. Both are small, fully
specified constructions (DSSE: secure-systems-lab/dsse; RFC 6962 section
2.1) -- implemented from their own published definitions, not from the
agent-evidence-vectors corpus.
"""
from __future__ import annotations

import hashlib


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body."""
    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        [
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


def leaf_hash(payload_type: str, payload: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + dsse_pae(payload_type, payload)).digest()


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def rfc6962_root(leaves: list[bytes]) -> bytes | None:
    """RFC 6962 MTH over leaf digests already hashed (0x00-prefixed).

    No duplicate-trailing-node padding: an odd split simply yields two
    differently sized subtrees, per RFC 6962's own recursive definition.
    """
    n = len(leaves)
    if n == 0:
        return None
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    left = rfc6962_root(leaves[:k])
    right = rfc6962_root(leaves[k:])
    assert left is not None and right is not None
    return hashlib.sha256(b"\x01" + left + right).digest()
