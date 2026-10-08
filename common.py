"""Shared helpers between aee_verify.py (GATE 0 + recompute) and
gate1.py (coverage validity), kept here to avoid a circular import.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from jcs import jcs_bytes

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class Invalid(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(cond: bool, code: str) -> None:
    if not cond:
        raise Invalid(code)


def is_hex64(s: Any) -> bool:
    return isinstance(s, str) and bool(HEX64_RE.match(s))


def sha256_jcs_hex(obj: Any) -> str:
    return hashlib.sha256(jcs_bytes(obj)).hexdigest()


def is_bmp_only(s: str) -> bool:
    return all(ord(c) <= 0xFFFF for c in s)


def utf16_sort_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def is_sorted_ascending_no_dup(arr: list[str]) -> bool:
    keys = [utf16_sort_key(s) for s in arr]
    return keys == sorted(keys) and len(set(arr)) == len(arr)
