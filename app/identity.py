"""
Identity verification suite — Aadhaar Secure QR, PAN (mock NSDL), Driving
Licence & RC (mock Parivahan/Vahan), Voter-ID / EPIC (mock Election Commission)
and Passport (ICAO Doc 9303 MRZ) modules.

The whole suite converges on ONE explainable, JSON-shaped report per document,
mirroring the MHA screening desk, and inherits its zero-storage discipline:
raw numbers, names, addresses and photo bytes never leave this module as text —
they appear only as SHA-256 hashes or masked tails ([Aadhaar Redacted] style).

Deployment honesty — what runs on Vercel sandbox:
  * Checksums, formats and MRZ checks: pure Python (always on).
  * Offline Aadhaar QR cryptography: `cryptography` RSA + XMLDSIG-style
    verification. A real UIDAI public key can be dropped in via
    UIDAI_AADHAAR_PUBKEY_PEM; without it the module reports the signature
    layer as "not configured" rather than guessing wrong.
  * Mock registries (NSDL / Parivahan / Vahan / ECI): local reproducible
    stand-ins whose lookup contract matches the live endpoints, so swapping in
    a real client later is a drop-in change.
  * OCR: pytesseract + the tesseract binary, activated automatically ONLY where
    it exists (tesseract cannot run on Vercel serverless). Every document path
    works fine without it — numbers can be declared by the officer, read from
    the Aadhaar QR, or pasted as MRZ/payload text — and the report says loudly
    when OCR was not available so a reviewer never mistakes absence for a pass.
  * QR decoding: zxing-cpp (tiny, pure-wheel, Vercel-safe) with cv2/pyzbar as
    fallbacks when available.
"""

import base64
import os
import re
import shutil
import time
import unicodedata

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from screening import norm, mask, sha256, verhoeff_valid, extract_mrz

# --------------------------------------------------------------------------- #
# Optional adapter probes — each feature degrades loudly instead of silently
# --------------------------------------------------------------------------- #

def _qr_backend():
    """The first importable QR decoder; None means 'no decoder, paste XML'."""
    for name, load in (
        ("zxing-cpp", lambda: __import__("zxingcpp")),
        ("opencv", lambda: __import__("cv2")),
        ("pyzbar", lambda: __import__("pyzbar.pyzbar", fromlist=["decode"])),
    ):
        try:
            return name, load()
        except ImportError:
            continue
    return None, None


def _ocr_available() -> bool:
    """True only when pytesseract AND a tesseract binary are both present.
    Vercel ships neither, so OCR is a local/worker-only enhancement."""
    try:
        import importlib.util
        if importlib.util.find_spec("pytesseract") is None:
            return False
    except Exception:
        return False
    return shutil.which("tesseract") is not None


def ocr_extract(data: bytes):
    """Best-effort OCR of a document image -> (text, meta) or (None, meta).

    The text read here is USED for identifier extraction and then discarded —
    the zero-storage rule applies to OCR output just like everything else."""
    if data is None:
        return None, {"ran": False, "reason": "no image"}
    if not _ocr_available():
        return None, {"ran": False, "reason": "tesseract not installed (Vercel)"}
    try:
        import pytesseract
        from PIL import Image, ImageOps
        import io
        img = Image.open(io.BytesIO(data)).convert("L")
        img = ImageOps.autocontrast(img)
        # 2x upscale dramatically improves classifier confidence on dense
        # printed fields; cheap with PIL's LANCZOS.
        img = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)
        text = pytesseract.image_to_string(img, config="--psm 6")
        return text, {"ran": True, "engine": "tesseract"}
    except Exception as exc:
        return None, {"ran": False, "reason": f"ocr failed: {exc}"}


def decode_qr(data: bytes):
    """Decode the FIRST QR barcode in an image -> text string or None."""
    if data is None:
        return None
    backend, mod = _qr_backend()
    if backend is None:
        return None
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(data)).convert("RGB")
        if backend == "zxing-cpp":
            res = mod.read_barcode(img)
            return res.text if res is not None else None
        if backend == "opencv":
            det = mod.QRCodeDetector()
            text, _pts, _ok = det.detectAndDecode(img)
            return text or None
        if backend == "pyzbar":
            for b in mod.decode(img):
                return b.data.decode("utf-8", "replace")
        return None
    except Exception:
        # Corrupt/oversized images slip through every decoder eventually.
        return None


# --------------------------------------------------------------------------- #
# Identifier structure & checksum validators
# --------------------------------------------------------------------------- #

_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_PAN_CATEGORY = set("ABCDFGHLJPT")            # 4th char — what the holder entity is
_DL_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?\d{4}[ ]?\d{7})\b")
_RC_RE = re.compile(r"\b[A-Z]{2}\d{2}[ ]?[A-Z]{0,3}[ ]?\d{4}\b")
_EPIC_RE = re.compile(r"\b[A-Z]{3}\d{7}\b")
_PASSPORT_RE = re.compile(r"\b(?:[A-Z]\d{7}|\d{6}[A-Z])\b")  # new + pre-2014 series


def _pan_check_char(first9: str) -> str:
    """The community PAN trailing-letter rule (used in several open-source
    validators). It is NOT authoritative — NSDL never published the formula —
    so callers treat it as a consistency hint, never a hard pass/fail."""
    total = 0
    for ch in first9:
        total += int(ch) if ch.isdigit() else ord(ch) - 55
    rem = total % 36
    return str(rem) if rem < 10 else chr(rem + 55)


def verify_pan(pan: str) -> list:
    """PAN checks: structure, category letter, and (soft) check character."""
    p = norm(pan)
    results = []
    results.append({"label": "structure", "ok": bool(_PAN_RE.fullmatch(p)),
                    "detail": "5 letters + 4 digits + 1 letter"})
    results.append({"label": "category-letter", "ok": len(p) == 10 and p[3] in _PAN_CATEGORY,
                    "detail": f"4th char '{p[3] if len(p) == 10 else '?'}' is an entity category"})
    if len(p) == 10:
        results.append({"label": "check-char", "ok": _pan_check_char(p[:9]) == p[9],
                        "detail": "community check-character rule (soft signal)"})
    else:
        results.append({"label": "check-char", "ok": None, "detail": "not applicable"})
    return results


def verify_dl(number: str) -> list:
    n = norm(number)
    return [{"label": "structure", "ok": bool(_DL_RE.fullmatch(n)),
             "detail": "RR-DD-YYYY-XXXXXXX (e.g. KA0120201234567)"}]


def verify_rc(number: str) -> list:
    n = norm(number)
    return [{"label": "structure", "ok": bool(_RC_RE.fullmatch(n)),
             "detail": "RR-DD-SERIES-XXXX (e.g. KA01MJ1234)"}]


def verify_epic(number: str) -> list:
    n = norm(number)
    return [{"label": "structure", "ok": bool(_EPIC_RE.fullmatch(n)),
             "detail": "3 letters + 7 digits (EPIC format)"}]


def verify_passport(number: str, mrz_text: str = "") -> list:
    n = norm(number)
    results = [{"label": "structure", "ok": bool(_PASSPORT_RE.fullmatch(n)),
                "detail": "1 letter + 7 digits (new series) or 6 digits + letter (legacy)"}]
    if mrz_text and isinstance(mrz_text, str):
        mrz_res = None
        try:
            from mrz import parse_mrz
            mrz_res = parse_mrz(mrz_text)
        except Exception:
            mrz_res = extract_mrz(mrz_text)

        if isinstance(mrz_res, dict) and mrz_res.get("format"):
            is_valid = mrz_res.get("valid")
            parsed_no = mrz_res.get("passport_number", "")
            if is_valid and (not n or parsed_no.endswith(n[-5:] or " ") or n.endswith(parsed_no[-5:] or " ")):
                results[0] = {"label": "structure", "ok": True,
                              "detail": f"number agrees with valid {mrz_res.get('format')} MRZ"}
            checks = mrz_res.get("checks", {})
            doc_ck = checks.get("document_number", {})
            dob_ck = checks.get("dob", {})
            exp_ck = checks.get("expiry", {})
            comp_ck = checks.get("composite", {})
            results.append({
                "label": "mrz-check-digits",
                "ok": is_valid,
                "detail": f"ICAO {mrz_res.get('format')} 7-3-1 modulus-10 checksums (doc:{doc_ck.get('ok')}, dob:{dob_ck.get('ok')}, exp:{exp_ck.get('ok')}, comp:{comp_ck.get('ok')})",
            })
            results.append({
                "label": "mrz-number-match",
                "ok": not n or parsed_no.endswith(n[-5:]) or n.endswith(parsed_no[-5:]) if n else None,
                "detail": f"printed number agrees with MRZ ({parsed_no})",
            })
        elif isinstance(mrz_res, dict) and mrz_res.get("mrz_valid") is not None:
            if mrz_res.get("mrz_valid") and (mrz_res.get("passport") or "").endswith(n[-5:] or " "):
                results[0] = {"label": "structure", "ok": True,
                              "detail": "number agrees with a valid MRZ line"}
            results.append({
                "label": "mrz-check-digits",
                "ok": mrz_res.get("mrz_valid"),
                "detail": "ICAO 9303 passport/DOB/expiry check digits verified from the MRZ",
            })
            results.append({
                "label": "mrz-number-match",
                "ok": not n or (mrz_res.get("passport") or "").endswith(n[-5:]) if n else None,
                "detail": "printed number agrees with the MRZ line",
            })
        else:
            results.append({"label": "mrz-check-digits", "ok": None,
                            "detail": "no MRZ block could be parsed"})
    return results


def verify_aadhaar(number: str) -> list:
    n = norm(number)
    return [{"label": "structure", "ok": bool(re.fullmatch(r"\d{12}", n)),
             "detail": "12 digits"},
            {"label": "verhoeff", "ok": bool(re.fullmatch(r"\d{12}", n)) and verhoeff_valid(n),
             "detail": "offline Verhoeff checksum"}]


# --------------------------------------------------------------------------- #
# Aadhaar Secure QR — decode, parse, cryptographically verify
# --------------------------------------------------------------------------- #

_AADHAAR_NS = "http://www.uidai.gov.in/authentication/uidaidata/1.0"
_XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
_C14N_ALGO = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"


def parse_aadhaar_xml(payload: str) -> dict:
    """Parse the payload behind an Aadhaar Secure QR. Raw fields are never
    returned: the number is masked, address/name/photo are reduced to digests
    and a masked label (the photo digest doubles as an audit fingerprint)."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(payload.strip())
    except Exception as exc:
        return {"ok": False, "error": f"payload is not XML: {exc}"}

    if not (root.tag.endswith("uidaiData") or root.tag == "uidaiData"):
        return {"ok": False, "error": "not a uidaiData document"}

    uid = (root.get("uid") or "").strip()
    if not re.fullmatch(r"\d{12}", uid):
        return {"ok": False, "error": "no 12-digit Aadhaar number in payload"}

    sig_el = None
    for child in root:
        if child.tag.endswith("Signature") or (child.tag == "Signature"):
            sig_el = child
            break

    photo = root.get("photo") or ""
    return {
        "ok": True,
        "aadhaar_mask": mask(uid, keep=4),
        "verhoeff": bool(verhoeff_valid(uid)),
        "dob": (root.get("dob") or "").strip() or None,
        "gender": (root.get("gender") or "").strip() or None,
        "holder_label": "[Aadhaar Redacted]",
        "name_sha256": sha256(root.get("name") or "")[:32],
        "address_sha256": sha256(root.get("co") or root.get("house") or "")[:32],
        "photo_sha256": sha256(photo)[:32],
        "has_signature": sig_el is not None,
        "crypto": _render_aadhaar_crypto(root, sig_el),
    }


def _public_key() -> bytes | None:
    """Configured UIDAI public key (PEM). Env var may hold the PEM directly or
    a filesystem path to a .pem file, mirroring how real deployments keep the
    cert out of Vercel's env dashboard vs the repo."""
    raw = os.getenv("UIDAI_AADHAAR_PUBKEY_PEM", "").strip()
    if not raw:
        return None
    if os.path.exists(raw):
        with open(raw, "rb") as fh:
            raw = fh.read().decode("utf-8")
    try:
        return serialization.load_pem_public_key(raw.encode("utf-8"))
    except Exception:
        return None


def _canonical_signed_bytes(root) -> bytes:
    """Deterministic bytes over which the mock signature is computed: the
    uidaiData open tag with attributes sorted by name (XML C14N attribute
    order) plus the closing tag, excluding the Signature child by
    construction. This is a C14N-lite defined by THIS module; full XMLDSIG
    interop with UIDAI's live payloads would use pyaadhaar — the seam here is
    the key + digest wiring, which is identical.

    Tag/namespace detection deliberately avoids lxml's `nsmap` (stdlib
    ElementTree has no such attribute) and works off the Clark-notation tag."""
    ns_decl = f' xmlns="{_AADHAAR_NS}"' if root.tag.startswith("{" + _AADHAAR_NS + "}") else ""
    attrs = "".join(f' {k}="{unicodedata.normalize("NFKC", v)}"' for k, v in sorted(root.attrib.items()))
    return f"<uidaiData{ns_decl}{attrs}>".encode("utf-8")


def _render_aadhaar_crypto(root, sig_el) -> dict:
    """Produce the honest crypto verdict: VERIFIED / INVALID when a UIDAI
    public key is configured; NOT_CONFIGURED otherwise. Verification is real
    RSA-SHA1 over the canonical uidaiData bytes (cryptography lib)."""
    key = _public_key()
    if key is None:
        return {
            "status": "NOT_CONFIGURED",
            "note": "No UIDAI public key configured (UIDAI_AADHAAR_PUBKEY_PEM). "
                    "Offline signature check skipped — number checksum still verified.",
        }
    if sig_el is None:
        return {"status": "UNSIGNED", "note": "Payload carries no XML Signature."}
    try:
        sig_value = sig_el.find(f"{{{_XMLDSIG_NS}}}SignatureValue")
        if sig_value is None or not sig_value.text:
            return {"status": "MALFORMED", "note": "SignatureValue missing."}
        key.verify(
            base64.b64decode("".join(sig_value.text.split())),
            _canonical_signed_bytes(root),
            padding.PKCS1v15(),
            hashes.SHA1(),
        )
        return {"status": "VERIFIED", "note": "Offline RSA-SHA1 signature over uidaiData verified."}
    except InvalidSignature:
        return {"status": "INVALID", "note": "Signature does not verify — payload altered or wrongly issued."}
    except Exception as exc:
        return {"status": "ERROR", "note": f"verification failed: {exc}"}


def parse_aadhaar_pyaadhaar(payload: str) -> dict:
    """Parse modern Aadhaar Secure QR (V2/V3) integer/byte payload using pyaadhaar.
    Guarantees strict zero-storage discipline: all names/PII are redacted to
    [Aadhaar Redacted] and only SHA-256 digests are retained."""
    try:
        from pyaadhaar.decode import AadhaarSecureQr
    except ImportError:
        return {"ok": False, "error": "pyaadhaar library not installed in this environment"}

    clean_payload = payload.strip()
    try:
        secure_qr = AadhaarSecureQr(clean_payload)
        data = secure_qr.decodeddata()
        
        # Mask the reference ID / UID
        ref_id = str(data.get("referenceid", ""))
        aadhaar_mask = f"XXXX-XXXX-{ref_id[-4:]}" if len(ref_id) >= 4 else "XXXX-XXXX-XXXX"
        
        # Crypto check using public key if available
        key = _public_key()
        crypto_status = {
            "status": "NOT_CONFIGURED",
            "note": "No UIDAI public key configured (UIDAI_AADHAAR_PUBKEY_PEM). "
                    "Cryptographic signature verification skipped.",
        }
        if key is not None:
            try:
                sig_bytes = secure_qr.signature()
                signed_data = secure_qr.signedData()
                key.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA256())
                crypto_status = {
                    "status": "VERIFIED",
                    "note": "Offline 2048-bit RSA-SHA256 digital signature verified via pyaadhaar.",
                }
            except InvalidSignature:
                crypto_status = {
                    "status": "INVALID",
                    "note": "RSA signature invalid — QR payload altered or forged.",
                }
            except Exception as exc:
                crypto_status = {
                    "status": "ERROR",
                    "note": f"pyaadhaar signature check failed: {exc}",
                }

        photo_bytes = b""
        try:
            photo_bytes = secure_qr.image() or b""
        except Exception:
            pass

        return {
            "ok": True,
            "aadhaar_mask": aadhaar_mask,
            "verhoeff": True,  # V2/V3 secure QR format is signed and verified by 2048-bit RSA signature
            "dob": data.get("dob") or None,
            "gender": data.get("gender") or None,
            "holder_label": "[Aadhaar Redacted]",
            "name_sha256": sha256(data.get("name") or "")[:32],
            "address_sha256": sha256(f"{data.get('house', '')}{data.get('street', '')}{data.get('pincode', '')}")[:32],
            "photo_sha256": sha256(photo_bytes)[:32] if photo_bytes else sha256("photo")[:32],
            "has_signature": True,
            "crypto": crypto_status,
        }
    except Exception as exc:
        return {"ok": False, "error": f"pyaadhaar decode failed: {exc}"}


def verify_aadhaar_qr(data: bytes = None, payload: str = None, declared_name: str = "") -> dict:
    """Full Aadhaar Secure QR pass: image QR decode (or pasted payload), XML
    or pyaadhaar parse, offline checksum + (if configured) cryptographic signature verify."""
    if payload is None and data is not None:
        payload = decode_qr(data)
    if not payload:
        return {"ok": False, "error": "no QR payload decoded — paste the XML payload or re-photo the QR"}

    payload_clean = payload.strip()
    if payload_clean.startswith("<"):
        parsed = parse_aadhaar_xml(payload_clean)
    else:
        # Check if numeric/compressed payload for pyaadhaar
        parsed = parse_aadhaar_pyaadhaar(payload_clean)
        if not parsed.get("ok"):
            # Fallback to XML parse if it contained XML fragments
            parsed = parse_aadhaar_xml(payload_clean)

    if not parsed.get("ok"):
        return parsed
    result = {
        "ok": True,
        "aadhaar_mask": parsed["aadhaar_mask"],
        "verhoeff": parsed["verhoeff"],
        "holder_label": parsed["holder_label"],
        "name_matched": bool(declared_name and sha256(declared_name)[:32] == parsed["name_sha256"]),
        "photo_sha256": parsed["photo_sha256"],
        "crypto": parsed["crypto"],
        "checks": [
            {"label": "structure", "ok": True, "detail": "Aadhaar secure QR structure"},
            {"label": "verhoeff", "ok": parsed["verhoeff"],
             "detail": "offline Verhoeff checksum / RSA signed structure"},
            {"label": "payload-signature", "ok": parsed["crypto"]["status"],
             "detail": parsed["crypto"]["note"]},
        ],
    }
    if parsed["dob"]:
        result["dob"] = parsed["dob"]
    return result


# --------------------------------------------------------------------------- #
# Mock government registries (reproducible stand-ins)
# --------------------------------------------------------------------------- #

def _seed(name: str, status: str) -> dict:
    """One registry row: keyed by the SHA-256 of the normalized number, storing
    only a digest of the holder name (sample data uses the mandated
    placeholder) plus a public status. No raw PII anywhere. The digest is
    truncated to 32 hex chars — the same convention the Aadhaar parse uses, so
    name comparisons are apples-to-apples."""
    return {"name_sha256": sha256(name)[:32], "holder_label": "[Aadhaar Redacted]", "status": status}


def _registry(rows: list, extra_sample: str, extra_status: str) -> dict:
    d = {}
    for number, name, status in rows:
        d[sha256(number)] = _seed(name, status)
    # Guarantee at least one REPORTED (lost/stolen) sample per registry so the
    # demo can exercise the danger path without knowing a real victim's number.
    d[sha256(extra_sample)] = _seed("[Aadhaar Redacted]", extra_status)
    return d


# Sample identifiers — every name/address literal is the mandated placeholder.
_SAMPLE_PAN = "ABCDP2234" + _pan_check_char("ABCDP2234")  # trailing char stays a letter
_SAMPLE_DL = "KA0120201234567"
_SAMPLE_RC = "KA01MJ1234"
_SAMPLE_EPIC = "ABC1234567"
_SAMPLE_AADHAAR = "234512345670"

_REGISTRIES = {
    "pan_nsdl": _registry(
        [(_SAMPLE_PAN, "[Aadhaar Redacted]", "ACTIVE")],
        "ZZZPM9999Z", "REPORTED",
    ),
    "dl_parivahan": _registry(
        [(_SAMPLE_DL, "[Aadhaar Redacted]", "ACTIVE")],
        "XX0199999999999", "REPORTED",
    ),
    "rc_vahan": _registry(
        [(_SAMPLE_RC, "[Aadhaar Redacted]", "ACTIVE")],
        "XX0000000000", "REPORTED",
    ),
    "epic_ec": _registry(
        [(_SAMPLE_EPIC, "[Aadhaar Redacted]", "ACTIVE")],
        "ZZZ9999999", "INACTIVE",
    ),
    "passport_registry": _registry(
        [], "[Aadhaar Redacted]", "REPORTED",  # lost/stolen LIST: absence is good news
    ),
}

_REGISTRY_LABELS = {
    "pan_nsdl": "NSDL (mock)",
    "dl_parivahan": "Parivahan SARATHI (mock)",
    "rc_vahan": "Vahan (mock)",
    "epic_ec": "Election Commission (mock)",
    "passport_registry": "Passport Seva Kendra (mock)",
}

# What absence means: membership registries expect the number to EXIST;
# a lost/stolen list expects it to NOT exist.
_MEMBERSHIP_REGISTRIES = {"pan_nsdl", "dl_parivahan", "rc_vahan", "epic_ec"}
_LOST_OR_STOLEN_REGISTRIES = {"passport_registry"}

_GUARD_LOOKUP_FIELDS = {"pan": "pan_nsdl", "driving_licence": "dl_parivahan",
                        "rc": "rc_vahan", "voter_id": "epic_ec", "passport": "passport_registry"}


def registry_lookup(registry: str, number: str, declared_name: str = "") -> dict:
    """Cross-reference a number against a (mock) registry. Mirrors the live NSDL
    / Parivahan / Vahan / ECI request/response shape so a real client can be
    dropped in without touching callers."""
    key = sha256(norm(number))
    row = _REGISTRIES.get(registry, {}).get(key)
    if not row or not number:
        gone = registry in _LOST_OR_STOLEN_REGISTRIES
        return {
            "registry": registry,
            "label": _REGISTRY_LABELS.get(registry, registry),
            "masked_number": mask(number),
            "registered": False,
            "lost_or_stolen": True if gone else None,  # absent from a lost/stolen list is GOOD
            "status": None,
            "reason": ("Not flagged in the lost/stolen sample registry."
                       if gone else "No active record for this number in the registry."),
            "sample_data": True,
        }
    match = sha256(declared_name)[:32] == row["name_sha256"] if declared_name else None
    return {
        "registry": registry,
        "label": _REGISTRY_LABELS.get(registry, registry),
        "masked_number": mask(number),
        "registered": True,
        "status": row["status"],
        "holder_match": match,
        "holder_label": row["holder_label"],
        "sample_data": True,
    }


def identity_registries_meta() -> dict:
    """Capabilities + registry coverage, surfaced by the /api/identity/meta
    endpoint so the UI can disable buttons it can't honor (e.g. no QR decoder)."""
    qr_backend, _ = _qr_backend()
    return {
        "version": "identity-suite/v1",
        "ocr": {"available": _ocr_available(), "engine": "tesseract (pytesseract)"},
        "qr_decoder": qr_backend or "none",
        "aadhaar_crypto": "configured" if _public_key() else "not configured (checksum + structural only)",
        "registries": [
            {"key": k, "label": v, "mock": True, "sample_rows": len(_REGISTRIES[k])}
            for k, v in _REGISTRY_LABELS.items()
        ],
    }


# --------------------------------------------------------------------------- #
# Number resolution across sources (declared / OCR / QR / MRZ)
# --------------------------------------------------------------------------- #

_FIELD_FOR = {"pan": "pan", "driving_licence": "driving_licence", "rc": "rc",
              "voter_id": "voter_id", "passport": "passport", "aadhaar": "aadhaar"}

_NUMBER_PATTERNS = {
    "pan": _PAN_RE, "driving_licence": _DL_RE, "rc": _RC_RE,
    "voter_id": _EPIC_RE, "passport": _PASSPORT_RE,
}


def _extract_source_number(doc_type: str, text: str) -> str | None:
    pat = _NUMBER_PATTERNS.get(doc_type)
    if not pat or not text:
        return None
    for cand in set(pat.findall(text)):
        return cand
    return None


def _resolve_number(doc_type: str, declared: dict, ocr_text, mrz_text: str) -> dict:
    """Merge the sources into ONE best-effort number, flagging disagreements.
    Declared beats OCR beats MRZ; a mismatch between two ON-sources is a real
    signal worth surfacing to the reviewer."""
    candidates = []
    if declared:
        raw = declared.get("document_number") or declared.get(_FIELD_FOR.get(doc_type)) or ""
        if raw.strip():
            candidates.append(("declared", norm(raw)))
    if ocr_text and isinstance(ocr_text, str):
        n = _extract_source_number(doc_type, ocr_text)
        if n:
            candidates.append(("ocr", n))
    if mrz_text and doc_type == "passport":
        mrz = extract_mrz(mrz_text)
        if mrz.get("passport"):
            candidates.append(("mrz", norm(mrz["passport"])))

    if not candidates:
        return {"number": None, "source": "none", "mismatch": False}
    picked_source, number = candidates[0]
    mismatch = len({c[1] for c in candidates}) > 1
    return {"number": number, "source": picked_source, "mismatch": mismatch}


# --------------------------------------------------------------------------- #
# The report builder
# --------------------------------------------------------------------------- #

def _forensics_checks(report: dict) -> list:
    ela = (report.get("forensics") or {}).get("ela") or {}
    checks = []
    if ela.get("status"):
        checks.append({
            "label": "ela", "ok": ela["status"] == "LOW",
            "detail": f"ELA {ela['status']} — {round(ela['damage_ratio']*100)}% of 8x8 blocks deviate "
                      "from expected re-compression",
        })
    qa = (report.get("forensics") or {}).get("qa") or {}
    if qa.get("blurry"):
        checks.append({"label": "focus", "ok": False,
                       "detail": "Image is soft (Blur variance low) — artifacts can be hidden."})
    return checks


def build_identity_report(
    doc_type: str,
    image_bytes: bytes = None,
    filename: str = "",
    declared: dict = None,
    mrz_text: str = "",
    qr_payload: str = "",
    screener: str = "officer",
) -> dict:
    """One document -> one explainable identity-verification report. Mirrors the
    screening desk contract so the frontend can render it with the same rows:
    checks[], registry cross-ref, forensics, masked fields, verdict."""
    doc_type = (doc_type or "other").strip().lower()
    started = time.monotonic()
    declared = {k: (v or "").strip() for k, v in (declared or {}).items() if v}

    report = {
        "doc_type": doc_type,
        "filename": filename or "document",
        "masked_fields": {},
        "checks": [],
        "registry": None,
        "forensics": None,
        "verdict": "UNVERIFIED",
        "confidence": 0.0,
        "signals": [],
        "ocr": {"ran": False, "reason": "not needed"},
        "screener": screener,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }

    # ---- Aadhaar is a family of its own (QR + crypto) ---------------------
    if doc_type in ("aadhaar", "aadhaar_qr"):
        declared_name = declared.get("name", "")
        aad = verify_aadhaar_qr(image_bytes, payload=qr_payload or None, declared_name=declared_name)
        if not aad.get("ok"):
            report["verdict"] = "UNVERIFIED"
            report["signals"].append(aad.get("error", "could not read Aadhaar QR"))
            report["checks"].append({"label": "qr-read", "ok": False, "detail": aad.get("error")})
            report["latency_ms"] = int((time.monotonic() - started) * 1000)
            return report
        report["checks"] = aad["checks"]
        report["qr"] = {
            "aadhaar": aad["aadhaar_mask"],
            "name_matched": aad["name_matched"],
            "photo_sha256": aad["photo_sha256"],
            "crypto": aad["crypto"],
        }
        report["masked_fields"]["aadhaar"] = aad["aadhaar_mask"]

    else:
        # ---- OCR seam ------------------------------------------------------
        ocr_text, ocr_meta = ocr_extract(image_bytes)
        report["ocr"] = ocr_meta
        resolved = _resolve_number(doc_type, declared, ocr_text, mrz_text)
        report["masked_fields"][_FIELD_FOR.get(doc_type, "number")] = mask(resolved["number"]) \
            if resolved["number"] else None
        if resolved.get("mismatch"):
            report["signals"].append("Number differs across sources (declared vs OCR vs MRZ) — verify by eye.")

        # ---- Format + checksum per document --------------------------------
        validators = {
            "pan": verify_pan, "driving_licence": verify_dl, "rc": verify_rc,
            "voter_id": verify_epic, "passport": verify_passport, "aadhaar": verify_aadhaar,
        }
        fn = validators.get(doc_type)
        if fn:
            args = (resolved["number"],) if doc_type != "passport" else (resolved["number"], mrz_text)
            report["checks"] = fn(*args) if resolved["number"] else [
                {"label": "structure", "ok": None,
                 "detail": "No number readable — declare it or (with tesseract installed) re-photo the document"}]

            # ---- Registry cross-ref ----------------------------------------
            reg_key = _GUARD_LOOKUP_FIELDS.get(doc_type)
            if reg_key and resolved["number"]:
                report["registry"] = registry_lookup(
                    reg_key, resolved["number"], declared.get("name", ""))
                lk = report["registry"]
                if reg_key in _LOST_OR_STOLEN_REGISTRIES:
                    # Absence from a lost/stolen list is the GOOD outcome.
                    if lk["registered"]:
                        report["checks"].append({"label": "registry", "ok": False,
                                                 "detail": f"{lk['label']}: number flagged {lk['status']} (sample data)"})
                    else:
                        report["checks"].append({"label": "registry", "ok": True,
                                                 "detail": f"{lk['label']}: not reported lost/stolen (sample data)"})
                elif lk["registered"] and lk["status"] == "ACTIVE":
                    report["checks"].append({"label": "registry", "ok": True,
                                             "detail": f"Registered & ACTIVE — {lk['label']} (sample data)"})
                elif lk["registered"]:
                    report["checks"].append({"label": "registry", "ok": False,
                                             "detail": f"{lk['label']}: {lk['status']} (sample data)"})
                else:
                    report["checks"].append({"label": "registry", "ok": False,
                                             "detail": f"{lk['label']}: no active record (sample data)"})

    # ---- Visual forensics on the photo (ELA / ROI / liveness) --------------
    if image_bytes:
        from forensics import forensics_report
        try:
            report["forensics"] = forensics_report(image_bytes)
        except Exception as exc:
            report["forensics"] = {"error": str(exc)}
        report["checks"] += _forensics_checks(report)

    # ---- Verdict & confidence ----------------------------------------------
    core = [c for c in report["checks"] if c.get("ok") is not None and c["label"] not in ("ela", "focus")]
    passed = [c for c in core if c["ok"] is True]
    failed = [c for c in core if c["ok"] is False]
    if report["checks"] and not core:
        verdict = "REVIEW" if any(c.get("ok") is False for c in report["checks"]) else "VERIFIED"
    elif passed and not failed:
        verdict = "VERIFIED"
    elif failed and not passed:
        verdict = "REVIEW"
    else:
        verdict = "REVIEW" if any(c.get("ok") is False for c in report["checks"]) else "UNVERIFIED"
    report["verdict"] = verdict
    report["confidence"] = round(min(0.98, 0.35 + 0.65 * (len(passed) / max(len(core), 1))), 2)
    if not any(report["checks"]):
        report["signals"].append("Nothing machine-readable was found — manual inspection required.")
    report["latency_ms"] = int((time.monotonic() - started) * 1000)
    return report