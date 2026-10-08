"""Self-authored tests for ijson_strict.py.

Every case here is hand-written from the spec's prose rules (Prerequisites
section of adversarial-execution-evidence.md), never copied or derived
from agent-evidence-vectors' shipped corpus. That matters for the blind
build this module supports: these are our own probes, not theirs.
"""
from ijson_strict import parse_strict, IJsonError


def ok(raw: bytes):
    return parse_strict(raw)


def fails(raw: bytes, code: str):
    try:
        parse_strict(raw)
    except IJsonError as e:
        assert e.code == code, f"expected {code}, got {e.code}: {e}"
        return
    raise AssertionError(f"expected IJsonError({code}), parsed cleanly")


def test_basic_object():
    r = ok(b'{"a": 1, "b": [1, 2, 3], "c": null, "d": true, "e": false}')
    assert r.value == {"a": 1, "b": [1, 2, 3], "c": None, "d": True, "e": False}
    assert r.max_depth == 2  # outer object (1) + the array "b" (2)


def test_duplicate_member_top_level():
    fails(b'{"a": 1, "a": 2}', "duplicate-member")


def test_duplicate_member_nested():
    fails(b'{"a": {"x": 1, "x": 2}}', "duplicate-member")


def test_depth_exactly_128_ok():
    # outermost "{" is depth 1; 127 more nested objects reaches 128.
    raw = b'{"k":' * 127 + b"1" + b"}" * 127
    raw = b"{" + b'"k":' * 0  # placeholder, build properly below
    opening = b'{"k":' * 127 + b"{}"
    closing = b"}" * 127
    raw = opening + closing
    r = ok(raw)
    assert r.max_depth == 128


def test_depth_129_rejected():
    opening = b'{"k":' * 128 + b"{}"
    closing = b"}" * 128
    fails(opening + closing, "nesting-too-deep")


def test_unpaired_high_surrogate():
    fails('{"a": "\\ud800"}'.encode(), "unpaired-surrogate")


def test_unpaired_low_surrogate():
    fails('{"a": "\\udc00"}'.encode(), "unpaired-surrogate")


def test_valid_surrogate_pair():
    # U+1F600 GRINNING FACE, as a UTF-16 surrogate pair escape.
    r = ok('{"a": "\\ud83d\\ude00"}'.encode())
    assert r.value["a"] == "\U0001F600"


def test_noncharacter_rejected_bmp():
    fails('{"a": "\\ufffe"}'.encode(), "noncharacter")


def test_noncharacter_rejected_supplementary():
    # U+1FFFE is a noncharacter in plane 1.
    fails('{"a": "\\ud83f\\udffe"}'.encode(), "noncharacter")


def test_fdd0_block_noncharacter():
    fails('{"a": "\\ufdd5"}'.encode(), "noncharacter")


def test_raw_control_char_rejected():
    fails(b'{"a": "x\x01y"}', "unescaped-control-char")


def test_unsafe_integer_rejected():
    fails(b'{"a": 9007199254740992}', "unsafe-integer")  # 2**53


def test_safe_integer_boundary_ok():
    r = ok(b'{"a": 9007199254740991}')  # 2**53 - 1
    assert r.value["a"] == 9007199254740991


def test_negative_unsafe_integer_rejected():
    fails(b'{"a": -9007199254740992}', "unsafe-integer")


def test_fractional_large_number_not_integer_profile():
    # Not integer-shaped (has a '.'), so the integer-magnitude rule does
    # not apply to it -- only literal integers are in scope per the text.
    r = ok(b'{"a": 9007199254740992.0}')
    assert r.value["a"] == 9007199254740992.0


def test_overlong_utf8_rejected():
    # Overlong 2-byte encoding of U+002F ('/'): C0 AF is invalid under
    # strict UTF-8 and must be rejected at the byte-decode step.
    fails(b'{"a": "\xc0\xaf"}', "ill-formed-utf8")


def test_trailing_garbage_rejected():
    fails(b'{"a": 1} {}', "trailing-garbage")


def test_bad_unicode_escape_not_four_hex():
    fails(b'{"a": "\\u123"}', "bad-unicode-escape")


if __name__ == "__main__":
    import sys
    import inspect

    mod = sys.modules[__name__]
    tests = [
        (name, fn)
        for name, fn in inspect.getmembers(mod, inspect.isfunction)
        if name.startswith("test_")
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"ok   {name}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
