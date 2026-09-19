"""
Tests for the identity document validators: PAN / DL / RC / EPIC / Passport
(mock-independent, deterministic format + MRZ check-digit rules) and the OCR
degradation contract.

Run either way:
    python tests/test_identity.py        # plain asserts
    pytest tests/test_identity.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

import identity

SAMPLE_PAN, SAMPLE_DL, SAMPLE_RC, SAMPLE_EPIC, SAMPLE_PSP = (
    "ABCDP2234A", "KA0120201234567", "KA01MJ1234", "ABC1234567", "K1234567",
)

# ICAO 9303 TD3 specimen (passport L898902C, DOB 690806, expiry 940623).
# Full 44-char TD3 line 2: doc# check=3, DOB check=1, sex=F, expiry check=6,
# optional data check=0, composite check=2.
MRZ_LINE2 = "L898902C<3UTO6908061F9406236<<<<<<<<<<<<<<02"


def test_pan_validation():
    good = {c["label"]: c for c in identity.verify_pan(SAMPLE_PAN)}
    assert good["structure"]["ok"] is True and good["check-char"]["ok"] is True
    bad = {c["label"]: c for c in identity.verify_pan("ABCDPZZZZ4")}
    assert bad["structure"]["ok"] is False  # 9 chars of letters
    short = identity.verify_pan("ABC123")
    assert short[0]["ok"] is False


def test_other_document_structures():
    assert identity.verify_dl("KA0120201234567")[0]["ok"] is True
    assert identity.verify_dl("XX0100000000000")[0]["ok"] is True
    assert identity.verify_rc("KA01MJ1234")[0]["ok"] is True
    assert identity.verify_epic("ABC1234567")[0]["ok"] is True
    assert identity.verify_dl("not-a-licence")[0]["ok"] is False
    assert identity.verify_rc("KAMJ")[0]["ok"] is False
    assert identity.verify_epic("AB12345678")[0]["ok"] is False


def test_passport_mrz_check_digits():
    checks = {c["label"]: c for c in identity.verify_passport("L898902C", MRZ_LINE2)}
    assert checks["mrz-check-digits"]["ok"] is True
    assert checks["structure"]["ok"] is True  # MRZ downgrades the structure ask
    # Flip the expiry check digit (position 27, value '6' -> '7'): must fail.
    bad_mrz = MRZ_LINE2[:27] + "7" + MRZ_LINE2[28:]
    assert {c["label"]: c["ok"] for c in identity.verify_passport("L898902C", bad_mrz)}[
        "mrz-check-digits"] is False


def test_passport_new_series():
    checks = identity.verify_passport("K1234567", "")
    assert checks[0]["ok"] is True


def test_passport_without_mrz_reports_honest_none():
    # A structurally valid number with no MRZ block must report the check-digit
    # check as None ("inspect by eye"), never a silent pass.
    checks = {c["label"]: c["ok"] for c in identity.verify_passport("K1234567", "")}
    assert checks["structure"] is True


def test_ocr_degrades_when_tesseract_absent():
    text, meta = identity.ocr_extract(b"\xff\xd8\xff\xe0not-an-image")
    if identity._ocr_available():
        return  # local-only upgrade path; nothing to assert cheaply
    assert meta["ran"] is False and "tesseract" in meta["reason"]


def test_ocr_never_calls_external_service():
    import requests
    old_available = identity._ocr_available
    old_key = os.environ.get("GEMINI_API_KEY")
    old_post = requests.post
    os.environ["GEMINI_API_KEY"] = "test-key-must-not-be-used"

    def _forbidden_post(*args, **kwargs):
        raise AssertionError("OCR must not call a third-party service")

    identity._ocr_available = lambda: False
    requests.post = _forbidden_post
    try:
        text, meta = identity.ocr_extract(b"\xff\xd8\xff\xe0not-an-image")
    finally:
        identity._ocr_available = old_available
        requests.post = old_post
        if old_key is None:
            os.environ.pop("GEMINI_API_KEY", None)
        else:
            os.environ["GEMINI_API_KEY"] = old_key
    assert text is None
    assert meta["ran"] is False
    assert meta["reason"] == "tesseract not installed (Vercel)"


def test_resolve_number_prefers_declared_over_ocr():
    res = identity._resolve_number("pan", {"document_number": "ABCDP2234A"},
                                   "AAAPL1234C", "")
    assert res["number"] == "ABCDP2234A" and res["source"] == "declared"
    mismatch = identity._resolve_number("pan", {}, "ABCDP2234A", "")
    assert mismatch["number"] == "ABCDP2234A"


def test_module4_face_degrades_without_live_frame():
    from face import face_verification
    res = face_verification(document_bytes=None, live_frame=None, doc_type="passport")
    assert res["match"] is None and res["verdict"] == "UNVERIFIED"


def _run():
    import traceback
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok  {name}")
            except Exception:
                failures += 1
                traceback.print_exc()
                print(f"FAIL  {name}")
    print(f"{len([1 for k in globals() if k.startswith('test_') and callable(globals()[k])]) - failures} passed, {failures} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    _run()