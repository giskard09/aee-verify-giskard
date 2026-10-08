"""Strict I-JSON (RFC 7493) parser for AEE v0.7 statement well-formedness.

Hand-rolled because stdlib json.loads:
  - silently keeps the last of duplicate object members (the AEE spec's
    Prerequisites require fail-closed rejection of ANY duplicate member,
    anywhere in the statement, at any depth);
  - has no nesting-depth accounting (the spec bounds it at 128, counting
    the outermost `{` as depth 1);
  - accepts an unpaired \\u surrogate escape as valid Python str content
    (a lone surrogate only surfaces later, if ever, as a .encode('utf-8')
    failure deep in some unrelated code path);
  - has no notion of the RFC 7493 safe-integer profile (|int| < 2**53) or
    the Unicode noncharacter exclusion (U+FDD0..U+FDEF, U+nFFFE, U+nFFFF).

This module parses raw bytes directly against RFC 8259 grammar plus the
I-JSON/AEE profile, and raises IJsonError (with a stable .code) on the
first violation found. It returns plain dict/list/str/int/float/bool/None
trees on success, dicts in original key order (duplicates having already
been rejected, so insertion order is unambiguous), plus the maximum
nesting depth observed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_NESTING_DEPTH = 128
SAFE_INT_BOUND = 2**53 - 1  # |value| MUST be < 2**53 per the predicate's text

_WHITESPACE = " \t\n\r"
_ESCAPES = {
    '"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
    "n": "\n", "r": "\r", "t": "\t",
}


class IJsonError(ValueError):
    def __init__(self, code: str, message: str, pos: int = -1):
        super().__init__(f"{code}: {message} (pos={pos})")
        self.code = code
        self.pos = pos


@dataclass
class ParseResult:
    value: Any
    max_depth: int


def _is_noncharacter(cp: int) -> bool:
    if 0xFDD0 <= cp <= 0xFDEF:
        return True
    return (cp & 0xFFFF) in (0xFFFE, 0xFFFF)


class _Parser:
    __slots__ = ("s", "n", "i", "max_depth")

    def __init__(self, text: str):
        self.s = text
        self.n = len(text)
        self.i = 0
        self.max_depth = 0

    def error(self, code: str, message: str) -> "IJsonError":
        return IJsonError(code, message, self.i)

    def skip_ws(self) -> None:
        s, n = self.s, self.n
        i = self.i
        while i < n and s[i] in _WHITESPACE:
            i += 1
        self.i = i

    def peek(self) -> str:
        if self.i >= self.n:
            raise self.error("unexpected-eof", "unexpected end of input")
        return self.s[self.i]

    def expect(self, ch: str) -> None:
        if self.i >= self.n or self.s[self.i] != ch:
            raise self.error("unexpected-token", f"expected {ch!r}")
        self.i += 1

    def parse_document(self) -> Any:
        self.skip_ws()
        value = self.parse_value(depth=0)
        self.skip_ws()
        if self.i != self.n:
            raise self.error("trailing-garbage", "content after top-level value")
        return value

    def parse_value(self, depth: int) -> Any:
        self.skip_ws()
        c = self.peek()
        if c == "{":
            return self.parse_object(depth)
        if c == "[":
            return self.parse_array(depth)
        if c == '"':
            return self.parse_string()
        if c == "-" or c.isdigit():
            return self.parse_number()
        if self.s.startswith("true", self.i):
            self.i += 4
            return True
        if self.s.startswith("false", self.i):
            self.i += 5
            return False
        if self.s.startswith("null", self.i):
            self.i += 4
            return None
        raise self.error("unexpected-token", f"unexpected character {c!r}")

    def _enter_container(self, depth: int) -> int:
        depth += 1
        if depth > MAX_NESTING_DEPTH:
            raise self.error("nesting-too-deep", f"nesting exceeds {MAX_NESTING_DEPTH}")
        if depth > self.max_depth:
            self.max_depth = depth
        return depth

    def parse_object(self, depth: int) -> dict:
        depth = self._enter_container(depth)
        self.expect("{")
        obj: dict[str, Any] = {}
        self.skip_ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return obj
        while True:
            self.skip_ws()
            if self.peek() != '"':
                raise self.error("unexpected-token", "expected object member name")
            key = self.parse_string()
            self.skip_ws()
            self.expect(":")
            value = self.parse_value(depth)
            if key in obj:
                raise self.error("duplicate-member", f"duplicate member {key!r}")
            obj[key] = value
            self.skip_ws()
            c = self.peek()
            if c == ",":
                self.i += 1
                continue
            if c == "}":
                self.i += 1
                break
            raise self.error("unexpected-token", "expected ',' or '}' in object")
        return obj

    def parse_array(self, depth: int) -> list:
        depth = self._enter_container(depth)
        self.expect("[")
        arr: list[Any] = []
        self.skip_ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return arr
        while True:
            arr.append(self.parse_value(depth))
            self.skip_ws()
            c = self.peek()
            if c == ",":
                self.i += 1
                continue
            if c == "]":
                self.i += 1
                break
            raise self.error("unexpected-token", "expected ',' or ']' in array")
        return arr

    def parse_string(self) -> str:
        self.expect('"')
        s, n = self.s, self.n
        out: list[str] = []
        i = self.i
        pending_high_surrogate: int | None = None
        while True:
            if i >= n:
                raise self.error("unexpected-eof", "unterminated string")
            c = s[i]
            cp_emit: int | None = None
            if c == '"':
                i += 1
                self.i = i
                if pending_high_surrogate is not None:
                    raise self.error("unpaired-surrogate", "lone high surrogate at string end")
                return "".join(out)
            if c == "\\":
                i += 1
                if i >= n:
                    raise self.error("unexpected-eof", "unterminated escape")
                esc = s[i]
                if esc == "u":
                    if i + 5 > n:
                        raise self.error("bad-unicode-escape", "truncated \\u escape")
                    hex4 = s[i + 1 : i + 5]
                    if len(hex4) != 4 or any(
                        ch not in "0123456789abcdefABCDEF" for ch in hex4
                    ):
                        raise self.error(
                            "bad-unicode-escape",
                            "\\u escape must be exactly four hex digits",
                        )
                    cp = int(hex4, 16)
                    i += 5
                    cp_emit = cp
                elif esc in _ESCAPES:
                    out_ch = _ESCAPES[esc]
                    i += 1
                    if pending_high_surrogate is not None:
                        raise self.error(
                            "unpaired-surrogate",
                            "high surrogate not followed by a low-surrogate escape",
                        )
                    out.append(out_ch)
                    continue
                else:
                    raise self.error("bad-escape", f"invalid escape \\{esc}")
            else:
                cp_emit = ord(c)
                i += 1

            assert cp_emit is not None
            if pending_high_surrogate is not None:
                if 0xDC00 <= cp_emit <= 0xDFFF:
                    combined = (
                        0x10000
                        + (pending_high_surrogate - 0xD800) * 0x400
                        + (cp_emit - 0xDC00)
                    )
                    pending_high_surrogate = None
                    if _is_noncharacter(combined):
                        raise self.error("noncharacter", f"U+{combined:06X} is excluded")
                    out.append(chr(combined))
                    continue
                raise self.error(
                    "unpaired-surrogate",
                    "high surrogate not followed by a low-surrogate escape",
                )
            if 0xD800 <= cp_emit <= 0xDBFF:
                pending_high_surrogate = cp_emit
                continue
            if 0xDC00 <= cp_emit <= 0xDFFF:
                raise self.error("unpaired-surrogate", "lone low surrogate")
            if cp_emit < 0x20:
                raise self.error(
                    "unescaped-control-char",
                    f"raw control character U+{cp_emit:04X} in string",
                )
            if _is_noncharacter(cp_emit):
                raise self.error("noncharacter", f"U+{cp_emit:06X} is excluded")
            out.append(chr(cp_emit))

    def parse_number(self) -> int | float:
        start = self.i
        s, n = self.s, self.n
        i = self.i
        if i < n and s[i] == "-":
            i += 1
        if i >= n or not s[i].isdigit():
            raise self.error("bad-number", "invalid number")
        if s[i] == "0":
            i += 1
        else:
            while i < n and s[i].isdigit():
                i += 1
        is_integer_literal = True
        if i < n and s[i] == ".":
            is_integer_literal = False
            i += 1
            if i >= n or not s[i].isdigit():
                raise self.error("bad-number", "invalid fraction")
            while i < n and s[i].isdigit():
                i += 1
        if i < n and s[i] in "eE":
            is_integer_literal = False
            i += 1
            if i < n and s[i] in "+-":
                i += 1
            if i >= n or not s[i].isdigit():
                raise self.error("bad-number", "invalid exponent")
            while i < n and s[i].isdigit():
                i += 1
        raw = s[start:i]
        self.i = i
        if is_integer_literal:
            value = int(raw)
            if abs(value) > SAFE_INT_BOUND:
                raise self.error(
                    "unsafe-integer",
                    f"integer magnitude {abs(value)} >= 2**53, out of I-JSON profile",
                )
            return value
        return float(raw)


def parse_strict(raw: bytes) -> ParseResult:
    """Parse raw bytes as a single I-JSON document.

    Raises IJsonError on: ill-formed UTF-8 (overlong forms, raw CESU-8
    surrogates -- rejected by Python's strict UTF-8 codec), any duplicate
    object member at any depth, nesting beyond 128, an unpaired \\u
    surrogate escape, a raw unescaped control character, a Unicode
    noncharacter in any string literal (member name or value), an integer
    literal of magnitude >= 2**53, or a syntactically malformed document.
    """
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IJsonError("ill-formed-utf8", str(exc), exc.start) from exc
    parser = _Parser(text)
    value = parser.parse_document()
    return ParseResult(value=value, max_depth=parser.max_depth)
