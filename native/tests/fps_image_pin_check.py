"""Check the native FPS image fingerprint against the immutable original ELF."""
from pathlib import Path
import hashlib
import json
import re
import sys

if sys.flags.optimize or sys.argv[1:]:
    raise RuntimeError("Assertions enabled and no arguments required")
native = Path(__file__).resolve().parents[1]
root = native.parent
source = native / "src/telltale_fps.cpp"
engine = root / "app/assets/guestlib/armeabi-v7a/libGameEngine.so"
GOLDEN = "2e54f21cef4c906b670d5386ac33cc4fea7450c4a8fe178713bcd2607a4c51bc"
SIZE = 17373252

def literal(text):
    matches = re.findall(r"expected = \{([^}]+)\};", text)
    assert len(matches) == 1
    body = matches[0]
    assert re.fullmatch(r"\s*(?:0x[0-9a-f]{2}\s*,\s*){31}0x[0-9a-f]{2}\s*", body)
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", body))

text = source.read_text(encoding="utf-8")
actual = hashlib.sha256(engine.read_bytes()).digest()
assert engine.stat().st_size == SIZE and actual.hex() == GOLDEN
assert literal(text) == actual, "Native image SHA literal differs from original ELF"
assert text.count("size != 17373252") == 1
bad = bytearray(actual); bad[23] ^= 0xb0
assert bytes(bad) != literal(text)
for invalid in ("", "expected = {0x00};", text + "\nexpected = {0x00};"):
    try:
        literal(invalid)
    except AssertionError:
        continue
    raise AssertionError("Malformed fingerprint literal accepted")
print(json.dumps({"status": "FPS_LITERAL_ACTUAL_ORIGINAL_ELF_AND_NEGATIVES_PASS",
    "engine_sha256": actual.hex(), "engine_bytes": SIZE, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    "scope": "Independent immutable ELF fingerprint; JNI/loaded binding/UI runtime unverified"}))
