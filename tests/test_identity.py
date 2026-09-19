"""
Tests for the identity verification suite: PAN / DL / RC / EPIC / Passport
validators, Aadhaar Secure QR parse + offline RSA-SHA1 verification, mock
registry cross-references and the end-to-end report builder.

Run either way:
    python tests/test_identity.py        # plain asserts
    pytest tests/test_identity.py

Every mock payload uses the mandated placeholder "[Aadhaar Redacted]" so no
real or invented citizen data ever appears in this file or the logs.
"""

import os
import sys
import io

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import identity
from screening import verhoeff_valid, sha256, mask

_AADHAAR_NS = "http://www.uidai.gov.in/authentication/uidaidata/1.0"
_XMLDSIG = "http://www.w3.org/2000/09/xmldsig#"

VALID_AADHAAR = "234512345670"
SAMPLE_PAN, SAMPLE_DL, SAMPLE_RC, SAMPLE_EPIC, SAMPLE_PSP = (
    "ABCDP2234A", "KA0120201234567", "KA01MJ1234", "ABC1234567", "K1234567",
)

# ICAO 9303 TD3 specimen (passport L898902C, DOB 690806, expiry 940623).
MRZ_LINE2 = "L898902C<3UTO6908061<9406236<"


def _base_aadhaar_xml(uid=VALID_AADHAAR):
    return (
        f'<uidaiData xmlns="{_AADHAAR_NS}" uid="{uid}" '
        'name="[Aadhaar Redacted]" dob="01/01/1990" gender="M" '
        'co="[Aadhaar Redacted]"></uidaiData>'
    )


def _signed_aadhaar_xml(private_key, uid=VALID_AADHAAR):
    """Build a mock but CRYPTOGRAPHICALLY VALID payload: sign the canonical
    (C#-faithful InnerXml-minus-s) bytes with the dev key, embed 's' as the
    last root attribute — mirroring how UIDAI-issued payloads carry it."""
    base = _base_aadhaar_xml(uid)
    canon = identity._canonical_signed_bytes(base)
    sig = private_key.sign(canon, padding.PKCS1v15(), hashes.SHA256())
    import base64 as b64
    sig_b64 = b64.b64encode(sig).decode("ascii")
    # First '>' in the string closes the root opening tag (attribute values
    # here hold no '>'), so this appends s="..." exactly where UIDAI puts it.
    return base.replace(">", f' s="{sig_b64}">', 1)


def test_canonical_bytes_match_csharp_innerxml_semantics():
    # .NET DocumentElement.InnerXml: no XML declaration, document attribute
    # order, self-closing roots emitted as '<tag ... />'.
    canon = identity._canonical_signed_bytes(
        '<?xml version="1.0"?><PrintLetterBarcodeData uid="123" pc="456"/>').decode()
    assert canon == '<PrintLetterBarcodeData uid="123" pc="456" />'
    # 's' is the ONLY attribute dropped; the rest keep order and values.
    canon2 = identity._canonical_signed_bytes(
        '<PrintLetterBarcodeData pc="456" s="AAA" uid="123"/>').decode()
    assert canon2 == '<PrintLetterBarcodeData pc="456" uid="123" />'


def test_aadhaar_flat_secure_qr_shape_verifies():
    """The real UIDAI Secure QR shape: flat, self-closing, no namespaces.
    This is the payload form the govt C# sample verifies — ours must agree."""
    import base64 as b64
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    unsigned = ('<PrintLetterBarcodeData uid="234512345670" name="[Aadhaar Redacted]" '
                'gender="M" yob="1990" co="[Aadhaar Redacted]" pc="110001"/>')
    canon = identity._canonical_signed_bytes(unsigned)
    assert canon.decode() == unsigned.replace("/>", " />")
    sig = b64.b64encode(key.sign(canon, padding.PKCS1v15(), hashes.SHA256())).decode("ascii")
    signed = unsigned.replace("/>", f' s="{sig}"/>')
    os.environ["UIDAI_AADHAAR_PUBKEY_PEM"] = pub_pem
    try:
        assert identity.parse_aadhaar_xml(signed)["crypto"]["status"] == "VERIFIED"
        # Flip one holder digit → signature must fail, not silently pass.
        bad = signed.replace('pc="110001"', 'pc="110002"', 1)
        assert identity.parse_aadhaar_xml(bad)["crypto"]["status"] == "INVALID"
    finally:
        os.environ.pop("UIDAI_AADHAAR_PUBKEY_PEM", None)


def test_verhoeff_smoke():
    assert verhoeff_valid(VALID_AADHAAR) is True
    assert verhoeff_valid("234512345671") is False
    assert verhoeff_valid("23451") is False


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
    # A wobbled expiry check digit must fail:
    bad_mrz = MRZ_LINE2[:24] + ("0",)[0] + MRZ_LINE2[25:]
    assert {c["label"]: c["ok"] for c in identity.verify_passport("L898902C", bad_mrz)}[
        "mrz-check-digits"] is False


def test_passport_new_series():
    checks = identity.verify_passport("K1234567", "")
    assert checks[0]["ok"] is True


def test_aadhaar_xml_parse_no_pii():
    parsed = identity.parse_aadhaar_xml(_base_aadhaar_xml())
    assert parsed["ok"] is True
    assert parsed["aadhaar_mask"] == mask(VALID_AADHAAR)
    assert parsed["holder_label"] == "[Aadhaar Redacted]"
    assert parsed["name_sha256"] == sha256("[Aadhaar Redacted]")[:32]
    assert parsed["verhoeff"] is True
    assert parsed["crypto"]["status"] == "NOT_CONFIGURED"


def test_aadhaar_xml_signature_verifies_and_rejects():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    os.environ["UIDAI_AADHAAR_PUBKEY_PEM"] = pub_pem
    try:
        good = identity.parse_aadhaar_xml(_signed_aadhaar_xml(key))
        assert good["crypto"]["status"] == "VERIFIED"
        # Tamper AFTER signing: mutate the uid attribute so the bytes on disk
        # differ from what the signature was computed over.
        tampered = _signed_aadhaar_xml(key).replace(VALID_AADHAAR, "234512345671", 1)
        assert identity.parse_aadhaar_xml(tampered)["crypto"]["status"] == "INVALID"
    finally:
        os.environ.pop("UIDAI_AADHAAR_PUBKEY_PEM", None)


def test_aadhaar_qr_without_decoder_degrades_loudly():
    res = identity.verify_aadhaar_qr(payload=None)
    assert res["ok"] is False and "QR" in res.get("error", "")


# UIDAI's public oKYC *test* certificate (HCL-AUA sample from the developer
# docs, expired 2019): NOT the production Secure-QR signing key, but a real
# X.509 .cer proving the loader accepts certificate PEMs, not just bare keys.
_HCL_TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIDhTCCAm2gAwIBAgIEYhPgKjANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJJ
TjESMBAGA1UECBMJS2FybmF0YWthMRIwEAYDVQQHEwlCYW5nYWxvcmUxEDAOBgNV
BAoTB2hjbC1hdWExEDAOBgNVBAsTB2hjbC1hdWExEDAOBgNVBAMTB2hjbC1hdWEw
HhcNMTgwMTAzMTMyNTQ5WhcNMTkwMTAzMTMyNTQ5WjBrMQswCQYDVQQGEwJJTjES
MBAGA1UECBMJS2FybmF0YWthMRIwEAYDVQQHEwlCYW5nYWxvcmUxEDAOBgNVBAoT
B2hjbC1hdWExEDAOBgNVBAsTB2hjbC1hdWExEDAOBgNVBAMTB2hjbC1hdWEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCBgQBr8wRk6QbtUsq6YvxEnY22
wr9mW62qVXpaWLVHYcbuVtBALf5LXFK3WnLAY15xKKQ9m9WZa8w2ZMpo20UePoLM
QSda0Gk4gFhe0Dl+czlNSLMnMlYc4qWrPrpUlFTi7KZKDLKrQKpQjacY/OKqUVYj
98IPsbp/IivpSvkwIaS3J1cyORNYCdtDLhpAbUUX0rCrJJXl3245BCJ/3jbtpQ+F
7Cc81sBVYT31b+L04G3h5Ih3hsFg24xrJES1WglsBZBNAbFnSE2CjMfNLUIikZjz
RfcQ5MZgU2/mGjlgGrLV/GX+8yQ0VRryWEmTNDDb0skGkY3ZQafgOHa0Vxg9AgMB
AAGjMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUagX6xg6PhyaYYI6cjAip
lBHT5S8wDQYJKoZIhvcNAQELBQADggEBAG1z3DQoXjo9u+QfflnymFvcwRcc+vQ1
xE/5n85G5Gl6PD1fw0HSOOEMbt2obx/L367UVX0+bSi0eG7lFADSfL9G5B+RN+wP
0ItLNoG8uc9F0SbQMUw21WLEnkQydjjg+7wp4PXPxyEtaRNYLjus7UbU/xnHTf6W
ltI9ngHEr1w69H9d17KiQsFBeGjg0qfH9CGhhKT2q0ETKWQSPI3fwCx3Z4AmS2nZ
tog4WzWZlOMLHoPeYsFGv4gTgzbRWX0jc6HZ0057TDo+XWErcSuxBSGX8jEGLfp2
tW4LOAE3autC9HsG4OQBiR+nEbMEHbm3Pv8meRvfgTV6P6qQiICeMaI=
-----END CERTIFICATE-----"""


def test_public_key_accepts_x509_certificate_pem():
    # A pasted .cer must yield a usable key object, not silent None; and a
    # payload signed by a DIFFERENT key must report INVALID (crypto ran),
    # never ERROR/NOT_CONFIGURED (crypto skipped).
    os.environ["UIDAI_AADHAAR_PUBKEY_PEM"] = _HCL_TEST_CERT
    try:
        assert identity._public_key() is not None
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        parsed = identity.parse_aadhaar_xml(_signed_aadhaar_xml(key))
        assert parsed["crypto"]["status"] == "INVALID"
    finally:
        os.environ.pop("UIDAI_AADHAAR_PUBKEY_PEM", None)


def test_registry_lookups():
    ok = identity.registry_lookup("pan_nsdl", SAMPLE_PAN)
    assert ok["registered"] is True and ok["status"] == "ACTIVE" and ok["sample_data"] is True
    unknown = identity.registry_lookup("pan_nsdl", "ABCDEZ9990")
    assert unknown["registered"] is False
    assert identity.registry_lookup("dl_parivahan", "XX0199999999999")["status"] == "REPORTED"
    assert identity.registry_lookup("rc_vahan", "KA01MJ1234")["status"] == "ACTIVE"
    assert identity.registry_lookup("voter_id_fake", "ABC1234567")["registered"] is False


def test_registry_name_match_with_placeholder():
    res = identity.registry_lookup("epic_ec", SAMPLE_EPIC, declared_name="[Aadhaar Redacted]")
    assert res["holder_match"] is True
    res2 = identity.registry_lookup("epic_ec", SAMPLE_EPIC, declared_name="Someone Else")
    assert res2["holder_match"] is False


def test_report_pan_end_to_end():
    rep = identity.build_identity_report("pan", image_bytes=None, filename="pan.jpg",
                                         declared={"document_number": SAMPLE_PAN})
    assert rep["verdict"] == "VERIFIED"
    assert rep["masked_fields"]["pan"] == mask(SAMPLE_PAN)
    assert rep["registry"]["status"] == "ACTIVE"
    assert any(c["label"] == "registry" and c["ok"] is True for c in rep["checks"])


def test_report_flags_reported_document():
    rep = identity.build_identity_report("driving_licence", image_bytes=None,
                                         filename="dl.jpg",
                                         declared={"document_number": "XX0199999999999"})
    assert rep["verdict"] in ("REVIEW", "VERIFIED")
    assert rep["registry"]["status"] == "REPORTED"
    assert any(c["label"] == "registry" and c["ok"] is False for c in rep["checks"])


def test_report_unverified_without_any_number():
    rep = identity.build_identity_report("rc", image_bytes=None, filename="rc.jpg", declared={})
    assert rep["verdict"] == "REVIEW" or rep["masked_fields"]["rc"] is None
    assert any(c["ok"] is None and "No number readable" in c["detail"] for c in rep["checks"])


def test_report_passport_mrz():
    rep = identity.build_identity_report("passport", image_bytes=None, filename="psp.jpg",
                                         declared={"document_number": "L898902C"},
                                         mrz_text=MRZ_LINE2)
    assert rep["verdict"] == "VERIFIED"
    assert any(c["label"] == "mrz-check-digits" and c["ok"] is True for c in rep["checks"])


def test_report_aadhaar_via_payload():
    rep = identity.build_identity_report("aadhaar", image_bytes=None, filename="aadhaar.jpg",
                                         declared={"name": "[Aadhaar Redacted]"},
                                         qr_payload=_base_aadhaar_xml())
    assert rep["verdict"] == "VERIFIED"
    assert rep["masked_fields"]["aadhaar"] == mask(VALID_AADHAAR)
    assert rep["qr"]["crypto"]["status"] == "NOT_CONFIGURED"


def test_report_ocr_degrades_gracefully():
    # No tesseract on this box (nor on Vercel): the report must say so and
    # still produce a usable REVIEW instead of crashing.
    buf = io.BytesIO()
    from PIL import Image
    import numpy as np
    Image.fromarray(np.zeros((200, 300, 3), dtype=np.uint8)).save(buf, "JPEG", quality=90)
    rep = identity.build_identity_report("pan", image_bytes=buf.getvalue(), filename="pan.jpg",
                                         declared={})
    assert "not" in rep["ocr"].get("reason", "") or rep["ocr"]["ran"] is False


def test_identity_meta_shape():
    meta = identity.identity_registries_meta()
    assert meta["version"].startswith("identity-suite")
    assert len(meta["registries"]) == 5
    assert all({"key", "label", "mock"} <= set(r) for r in meta["registries"])


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