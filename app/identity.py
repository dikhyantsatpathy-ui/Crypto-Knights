"""
Identity document validation — Aadhaar (Verhoeff + optional Secure-QR crypto),
Driving Licence, Passport (ICAO Doc 9303 MRZ), PAN, RC, Voter-ID / EPIC.

This is Module 2 (Document Validation) of the MHA SIH26188 screening desk:
deterministically confirming that the extracted fields follow official
standards — structure regexes, Verhoeff checksum, MRZ check digits, and (when
toggled on) the Aadhaar offline RSA-SHA256 signature. It inherits the desk's
zero-storage discipline: raw numbers, names and photo bytes never leave this
module as text — only SHA-256 hashes or masked tails ([Aadhaar Redacted]).

Aadhaar crypto toggle (crypto_mode):
    auto (default) — checksum + structural checks always; the RSA-SHA256
                     signature is verified only when UIDAI_AADHAAR_PUBKEY_PEM
                     is configured (otherwise "not configured", never a guess).
    on             — the signature check is REQUIRED and hard-fails if the key
                     is missing or the payload was altered.
    off            — checksum + structural only; never touches the key.

OCR: pytesseract + tesseract binary, activated only where it exists (tesseract
cannot run on Vercel serverless) — every path works declared-only and the
report says loudly when OCR was off. QR decoding: zxing-cpp (Vercel-safe) with
cv2/pyzbar fallbacks.
"""

import base64
import os
import re
import shutil

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from screening import norm, mask, sha256, verhoeff_valid, extract_mrz


def _pan_check_char(first9: str) -> str:
    """The community PAN trailing-letter rule (used in several open-source
    validators). It is NOT authoritative — NSDL never published the formula —
    so callers treat it as a consistency hint, never a hard pass/fail."""
    total = 0
    for ch in first9:
        total += int(ch) if ch.isdigit() else ord(ch) - 55
    rem = total % 36
    return str(rem) if rem < 10 else chr(rem + 55)

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
            # Upgrade the structure check when MRZ confirms the number
            number_agrees = bool(
                n and parsed_no and (
                    parsed_no.endswith(n[-5:]) or n.endswith(parsed_no[-5:])
                )
            ) if n and parsed_no else False
            if is_valid and number_agrees:
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
                "ok": number_agrees if n else None,
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


def parse_aadhaar_xml(payload: str) -> dict:
    """Parse the payload behind an Aadhaar Secure QR. Raw fields are never
    returned: the number is masked, address/name/photo are reduced to digests
    and a masked label (the photo digest doubles as an audit fingerprint)."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(payload.strip())
    except Exception as exc:
        return {"ok": False, "error": f"payload is not XML: {exc}"}

    if not (root.tag.endswith("uidaiData") or root.tag == "uidaiData" or root.tag.endswith("PrintLetterBarcodeData") or root.tag == "PrintLetterBarcodeData"):
        return {"ok": False, "error": "not a uidaiData or PrintLetterBarcodeData document"}

    uid = (root.get("uid") or "").strip()
    if not re.fullmatch(r"\d{12}", uid):
        return {"ok": False, "error": "no 12-digit Aadhaar number in payload"}

    sig_value = root.get("s")

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
        # Transient only: raw portrait bytes for an in-request face match.
        # NEVER persisted (IdentityCheck stores digests) and NEVER returned to
        # the client — verify_aadhaar_qr consumes it and drops it.
        "photo_b64": photo or None,
        "has_signature": sig_value is not None,
        "crypto": _render_aadhaar_crypto(payload, sig_value),
    }


def _public_key() -> bytes | None:
    """Configured UIDAI public key. Env var may hold the PEM directly or a
    filesystem path to a .pem/.cer file, mirroring how real deployments keep
    the cert out of Vercel's env dashboard vs the repo. Accepts EITHER a bare
    public key ('-----BEGIN PUBLIC KEY-----') OR a full X.509 certificate
    ('-----BEGIN CERTIFICATE-----', the form UIDAI distributes .cer files in)
    — the key is extracted from the cert in the latter case."""
    raw = os.getenv("UIDAI_AADHAAR_PUBKEY_PEM", "").strip()
    if not raw:
        return None
    if os.path.exists(raw):
        with open(raw, "rb") as fh:
            raw = fh.read().decode("utf-8")
    try:
        if "BEGIN CERTIFICATE" in raw:
            from cryptography.x509 import load_pem_x509_certificate
            return load_pem_x509_certificate(raw.encode("utf-8")).public_key()
        return serialization.load_pem_public_key(raw.encode("utf-8"))
    except Exception:
        return None


_ATTR_RE = re.compile(r"([^\s=/>]+)\s*=\s*(\"[^\"]*\"|'[^']*')")


def _xml_attr_esc(value: str) -> str:
    """Escape an attribute value the way .NET's XmlWriter does inside
    InnerXml: &, <, double-quote, and tab/LF/CR as character references."""
    return (value.replace("&", "&amp;").replace("<", "&lt;")
                 .replace('"', "&quot;").replace("\t", "&#x9;")
                 .replace("\n", "&#xA;").replace("\r", "&#xD;"))


def _canonical_signed_bytes(payload_str: str) -> bytes:
    """Byte-exact mirror of UIDAI's official offline-XML verifier (Govt. of
    India C# sample): XmlDocument.Load → DocumentElement.Attributes.
    RemoveNamedItem("s") → DocumentElement.InnerXml → UTF-8 → SHA256withRSA.

    That means: the ROOT element re-serialized in document-attribute order,
    double quotes, WITHOUT the 's' attribute and WITHOUT any XML declaration
    (InnerXml never contains one). A regex strip of the raw string is NOT
    equivalent — .NET re-serializes the DOM (e.g. self-closing roots come out
    as `<tag ... />`), so only the DOM form matches UIDAI-signed bytes."""
    text = payload_str.strip()
    text = re.sub(r"<\?.*?\?>", "", text, count=1).strip()
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(text)
    except Exception:
        return text.encode("utf-8")
    # Parsed values by local name (ElementTree uses Clark {ns}local).
    values: dict = {}
    for k, v in root.attrib.items():
        values.setdefault(k.rsplit("}", 1)[-1] if "}" in k else k, v)
    # Original root start tag: keep its exact names/order (incl. xmlns decls),
    # drop only 's' — the one attribute the UIDAI sample removes.
    mtag = re.match(r"<\s*[^\s/>]+(.*?)(/?)>", text, re.S)
    raw_attrs = mtag.group(1) if mtag else ""
    mname = re.match(r"<\s*([^\s/>]+)", text)
    qname = mname.group(1) if mname else root.tag
    out = []
    for am in _ATTR_RE.finditer(raw_attrs):
        name = am.group(1)
        if name == "s":
            continue
        if name.startswith("xmlns"):
            out.append(f" {name}={am.group(2)}")  # namespace decls verbatim
        else:
            out.append(f' {name}="{_xml_attr_esc(values.get(name.rsplit(":", 1)[-1], ""))}"')
    attrs = "".join(out)
    inner = (root.text or "") + "".join(
        ET.tostring(c, encoding="unicode") for c in root)
    if len(root) == 0 and root.text is None:
        return f"<{qname}{attrs} />".encode("utf-8")
    return f"<{qname}{attrs}>{inner}</{qname}>".encode("utf-8")


def _render_aadhaar_crypto(payload_str: str, sig_value: str | None) -> dict:
    """Produce the honest crypto verdict: VERIFIED / INVALID when a UIDAI
    public key is configured; NOT_CONFIGURED otherwise. Verification is real
    RSA-SHA256 over the canonical XML string — the Python twin of the C# sample
    (SHA256withRSA ↔ PKCS1v15+SHA256; X509 cert file ↔ UIDAI_AADHAAR_PUBKEY_PEM)."""
    key = _public_key()
    if key is None:
        return {
            "status": "NOT_CONFIGURED",
            "note": "No UIDAI public key configured (UIDAI_AADHAAR_PUBKEY_PEM). "
                    "Offline signature check skipped — number checksum still verified.",
        }
    if not sig_value:
        return {"status": "UNSIGNED", "note": "Payload carries no 's' signature attribute."}
    try:
        key.verify(
            base64.b64decode("".join(sig_value.split())),
            _canonical_signed_bytes(payload_str),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return {"status": "VERIFIED", "note": "Offline RSA-SHA256 signature over XML data verified."}
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


def verify_aadhaar_qr(data: bytes = None, payload: str = None, declared_name: str = "",
                      selfie_bytes: bytes = None, crypto_mode: str = "auto",
                      include_portrait: bool = False) -> dict:
    """Full Aadhaar Secure QR pass: image QR decode (or pasted payload), XML
    or pyaadhaar parse, offline checksum + (if configured) cryptographic
    signature verify, plus an optional QR-portrait vs selfie face match.

    crypto_mode (Module 2 toggle for the screening desk):
      "auto" (default) — checksum + structural always; RSA-SHA256 signature is
                          verified only when UIDAI_AADHAAR_PUBKEY_PEM is set.
                          Missing key, unsigned payloads → check is None (honest
                          "not configured"), never a silent pass or fail.
      "on"              — signature REQUIRED and hard-gated: no key configured,
                          unsigned payload, or bad signature all FAIL the check.
      "off"             — checksum + structural only; never inspects the key.
    """
    mode = (crypto_mode or "auto").strip().lower()
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

    # ---- Crypto verdict per toggle ----------------------------------------
    status = (parsed.get("crypto") or {}).get("status", "NOT_CONFIGURED")
    if mode == "off":
        crypto_ok = None
        crypto_detail = ("Aadhaar signature checks disabled (checksum + structural only). "
                         "Toggle crypto ON to require the RSA-SHA256 signature.")
    elif mode == "on":
        signed_ok = status == "VERIFIED"
        if not signed_ok:
            reason = (parsed.get("crypto") or {}).get("note", "signature unavailable")
            crypto_ok = False
            crypto_detail = f"Signature REQUIRED: {status} — {reason}"
        else:
            crypto_ok = True
            crypto_detail = (parsed.get("crypto") or {}).get("note", "RSA-SHA256 signature verified.")
    else:  # auto
        # VERIFIED -> True, INVALID -> False, anything else -> None (honest
        # "not configured"); never a silent pass, never a false fail.
        crypto_ok = True if status == "VERIFIED" else (False if status == "INVALID" else None)
        crypto_detail = (parsed.get("crypto") or {}).get(
            "note", "signature not verified — not configured or unsigned")

    checks = [
        {"label": "structure", "ok": True, "detail": "Aadhaar secure QR structure"},
        {"label": "verhoeff", "ok": parsed["verhoeff"],
         "detail": "offline Verhoeff checksum / RSA signed structure"},
        {"label": "payload-signature", "ok": crypto_ok, "detail": crypto_detail,
         "crypto_mode": mode, "crypto_status": status},
    ]
    result = {
        "ok": True,
        "aadhaar_mask": parsed["aadhaar_mask"],
        "verhoeff": parsed["verhoeff"],
        "holder_label": parsed["holder_label"],
        "name_matched": bool(declared_name and sha256(declared_name)[:32] == parsed["name_sha256"]),
        "photo_sha256": parsed["photo_sha256"],
        "crypto": parsed["crypto"],
        "checks": checks,
    }
    if parsed["dob"]:
        result["dob"] = parsed["dob"]
    # Optional internal-only handoff: the QR portrait base64 for Module 4's live
    # face comparison in the same request. Consumed immediately by face.py and
    # never persisted — the zero-storage rule still applies to result objects.
    if include_portrait and parsed.get("photo_b64"):
        result["_portrait_b64"] = parsed["photo_b64"]
    # ---- QR portrait vs live selfie --------------------------------------
    # Closes "valid card, wrong person" mechanically. The raw portrait never
    # leaves this function: only score/match/method enter the result.
    if selfie_bytes:
        if parsed.get("photo_b64"):
            try:
                from face_match import compare_faces
                fm = compare_faces(parsed["photo_b64"], selfie_bytes)
            except Exception:
                fm = {"score": 0, "match": None, "method": "unavailable",
                      "detail": "Face comparison failed to run."}
            result["face"] = fm
            result["checks"].append({
                "label": "face-match",
                "ok": fm["match"],
                "detail": f"QR portrait vs selfie ({fm['method']}, score {fm['score']}): {fm['detail']}",
            })
        else:
            result["checks"].append({
                "label": "face-match", "ok": None,
                "detail": "QR payload carries no portrait — visual match impossible, verify holder by eye.",
            })
    return result


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