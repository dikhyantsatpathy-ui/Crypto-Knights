"""
MHA identity-document screening pipeline — SIH 2026 PS SIH26188.

"AI-Based Fake Identity and Document Screening System" (Ministry of Home
Affairs). The flow is the statement's own: Upload -> Extract -> Analyze ->
Verify -> Assess Risk. Every conclusion is *explainable*: each risk point
carries a human-readable reason, the same file is cross-referenced against
the provenance ledger AND the AI detectors, and the system keeps an audit
trail while storing ZERO raw document bytes or text (only SHA-256 hashes,
masked identifiers, and explainable signals — same zero-storage philosophy
as the rest of nocap).

Identifier validation is deliberately deterministic and transparent (checksum
+ format rules) so screening works offline, explains itself to a human
reviewer, and stays open to every downstream model later swapped in.
"""

import hashlib
import io
import json
import re
import time
import unicodedata
import uuid

# AI-detection + document-awareness live inside app/main.py (single-file
# backend). They are imported lazily inside run_screening() at call time, so
# main.py -> screening.py -> main.py circular import is avoided.

# --------------------------------------------------------------------------- #
# Identifier normalization & masks
# --------------------------------------------------------------------------- #

_PUNCT = str.maketrans("", "", " -/\\._:()")


def norm(value):
    """Collapse spaces/punctuation and uppercase — 'ka-01/2020/1234567' vs
    'KA 012020 1234567' must match as the same identifier."""
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFKC", value).translate(_PUNCT).strip().upper()


def mask(value: str, keep: int = 4) -> str:
    """Display-safe mask: keep only the last `keep` characters."""
    v = norm(value)
    return ("*" * (len(v) - keep)) + v[-keep:] if len(v) > keep else v


def sha256(value: str) -> str:
    return hashlib.sha256(norm(value).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Checksum utilities (deterministic, explainable)
# --------------------------------------------------------------------------- #

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(digits: str) -> bool:
    """True when the 12-digit string passes the Verhoeff checksum (Aadhaar)."""
    if not digits.isdigit() or len(digits) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return _INV[c] == 0


def mrz_checkdigit(field: str) -> int:
    """ICAO 9303 check digit over an MRZ field (weights 7,3,1 repeating)."""
    weights = (7, 3, 1)
    total = 0
    for i, ch in enumerate(field):
        if ch == "<":
            v = 0
        elif ch.isdigit():
            v = ord(ch) - 48
        else:
            v = ord(ch) - 55  # A=10 .. Z=35
        total += v * weights[i % 3]
    return total % 10


# --------------------------------------------------------------------------- #
# Field extraction (regex + checksums over pdf text and declared fields)
# --------------------------------------------------------------------------- #

_AADHAAR_RE = re.compile(r"\b[2-9]\d{11}(?![0-9])")
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z](?![0-9])")
_DL_RE = re.compile(r"\b[A-Z]{2}\d{2}[ ]?\d{4}[ ]?\d{7}(?![0-9])")
_PASSPORT_LITE_RE = re.compile(r"\b[A-Z][0-9]{7}(?![0-9])")
_EPIC_RE = re.compile(r"\b[A-Z]{3}\d{7}(?![0-9])")
_PHONE_RE = re.compile(r"\b[6-9]\d{9}(?![0-9])")
_DOB_RE = re.compile(r"\b(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})\b|\b(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})\b")
_MRZ_LINE2_RE = re.compile(r"([A-Z0-9<]{9})(\d)([A-Z<]{3})(\d{6})(\d)([A-Z<]{1})(\d{6})(\d)[A-Z0-9<]*")


def _days_in_month(m: int, y: int) -> int:
    if m in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if m in (4, 6, 9, 11):
        return 30
    leap = (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0)
    return 29 if leap else 28


def _valid_date(y: int, m: int, d: int) -> bool:
    if not (1900 <= y <= 9999) or not (1 <= m <= 12) or d < 1:
        return False
    return d <= _days_in_month(m, y)


def _first_date(text: str) -> str | None:
    """Best DOB candidate as YYYY-MM-DD.

    A printed identity document carries several dates — issue, expiry, DOB.
    The DOB is the OLDEST and must lie in the past, so pick the oldest
    plausible date instead of the first one; otherwise an expiry printed
    before the DOB ("VALID TILL: 31-12-2031 / DOB: 15-08-1990") is mistaken
    for a future date of birth and adds a false +30 risk. When nothing is in
    the past (a pure future-date scan), fall back to the first date so the
    future-DOB signal can still fire."""
    picks = []
    for m in _DOB_RE.finditer(text):
        g = m.groups()
        if g[0] is not None:  # DMY
            d, mo, y = int(g[0]), int(g[1]), int(g[2])
        else:                   # YMD
            y, mo, d = int(g[3]), int(g[4]), int(g[5])
        if _valid_date(y, mo, d):
            picks.append((y, mo, d))
    if not picks:
        return None
    y, mo, d = min(picks)
    if (y, mo, d) <= tuple(int(x) for x in _today().split("-")):
        return f"{y:04d}-{mo:02d}-{d:02d}"
    return f"{picks[0][0]:04d}-{picks[0][1]:02d}-{picks[0][2]:02d}"


def extract_mrz(text: str) -> dict:
    """Parse an ICAO TD3 MRZ (passport). Validates passport/DOB/expiry
    check digits — a tampered or photoshopped zone fails these."""
    out = {}
    for m in _MRZ_LINE2_RE.finditer(text):
        pno, ck_p, _nat, dob, ck_d, _sex, exp, ck_e = m.groups()
        if not pno.rstrip("<"):
            continue  # a number field that is all '<' filler is not a passport
        pno_ok = mrz_checkdigit(pno) == int(ck_p)
        dob_ok = mrz_checkdigit(dob) == int(ck_d)
        exp_ok = mrz_checkdigit(exp) == int(ck_e)
        out = {
            "passport": pno.rstrip("<"),   # drop ICAO '<' filler before masking/hashing
            "mrz_dob": dob,
            "mrz_passport_ck": pno_ok,
            "mrz_dob_ck": dob_ok,
            "mrz_expiry_ck": exp_ok,
            "mrz_valid": pno_ok and dob_ok and exp_ok,
        }
        if out.get("mrz_valid"):
            break  # first structurally valid MRZ wins
    return out


def _match_identifiers(source: str) -> dict:
    """Run the identifier regexes over one text variant; first valid wins."""
    hits = {}
    for cand in set(_AADHAAR_RE.findall(source)):
        if verhoeff_valid(cand):
            hits["aadhaar"] = cand
            break
    for cand in set(_PAN_RE.findall(source)):
        hits["pan"] = cand          # 10-char structure already proven
        break
    for cand in set(_DL_RE.findall(source)):
        hits["driving_licence"] = cand
        break
    for cand in set(_PASSPORT_LITE_RE.findall(source)):
        hits["passport"] = cand     # demoted to a review signal if MRZ missing
        break
    for cand in set(_EPIC_RE.findall(source)):
        hits["voter_id"] = cand     # EPIC: 3 letters + 7 digits, deterministic
        break
    for cand in set(_PHONE_RE.findall(source)):
        hits["phone"] = cand
        break
    return hits


def extract_fields(text: str) -> dict:
    """Deterministic extraction of Indian identity identifiers from text.
    Returns only validated/masked-able raw values plus explainable flags."""
    text = unicodedata.normalize("NFKC", text or "")
    # Identifiers are matched over three views of the same text because every
    # printed format is a little different:
    #   raw   — the printed layout keeps its word boundaries ("MH01 2015 0001234")
    #   clean — punctuation/spacing collapsed ("2345 1234 5670" -> "234512345670")
    #   spaced— letter->digit boundaries re-introduced so \b survives a label
    #           that was glued to the number ("References234512345670").
    # Date/MRZ regexes run on the RAW text only, because their separators ('/'/
    # '-') and '<' filler are significant.
    clean = norm(text)
    spaced = re.sub(r"(?i)(?<=[a-z])(?=\d)", " ", clean)
    found = {"aadhaar": None, "pan": None, "driving_licence": None,
             "passport": None, "voter_id": None, "phone": None, "dob": None}
    for src in (text, clean, spaced):
        for key, val in _match_identifiers(src).items():
            if val and not found.get(key):
                found[key] = val

    dob = _first_date(text)
    if dob:
        found["dob"] = dob

    mrz = extract_mrz(text)
    if mrz:
        found["passport"] = mrz.pop("passport", found["passport"])
        found.update(mrz)
        # A structurally valid MRZ carries an authoritative DOB (YYMMDD) that
        # even a text-free scan/passport can contribute to evidence coverage.
        if mrz.get("mrz_valid") and mrz.get("mrz_dob") and not found.get("dob"):
            yymmdd = mrz["mrz_dob"]
            century = "19" if int(yymmdd[:2]) > int(time.strftime("%y")) else "20"
            found["dob"] = f"{century}{yymmdd[:2]}-{yymmdd[2:4]}-{yymmdd[4:6]}"
    return found


# --------------------------------------------------------------------------- #
# Risk assessment
# --------------------------------------------------------------------------- #

def _today():
    return time.strftime("%Y-%m-%d")


def _grade(score: int) -> str:
    return "CLEAR" if score <= 30 else ("REVIEW" if score <= 62 else "FLAGGED")


def run_screening(db, data: bytes, filename: str, doc_type: str | None,
                  checkpoint: str | None, declared: dict | None,
                  screener: str | None = None) -> dict:
    """Full Upload->Extract->Analyze->Verify->AssessRisk pass. Returns a
    report dict AND persists an immutable ScreeningReport row."""
    try:
        from app.main import LedgerBlock, WatchlistEntry, ScreeningReport
    except ImportError:  # bare-module invocation (tests / direct run)
        from main import LedgerBlock, WatchlistEntry, ScreeningReport

    file_hash = hashlib.sha256(data).hexdigest()
    ext = (filename or "").lower().rsplit(".", 1)[-1] if "." in (filename or "") else ""
    started = time.monotonic()

    # ---- Verify against the provenance ledger ------------------------------
    block = db.query(LedgerBlock).filter_by(file_hash=file_hash).first()
    ledger_status = "AUTHENTIC" if block and not block.is_revoked else (
        "REVOKED" if block else "UNKNOWN")

    # ---- Extract: pypdf for PDFs; AI photo scan + document-awareness for images
    scanned, ai_det = {}, {"ran": False, "ai_suspected": False, "ai_score": 0,
                           "model": None, "provider": None, "explanation": "No image.",
                           "latency_ms": 0}
    pdf_no_text = False
    if ext == "pdf":
        try:
            from pypdf import PdfReader
            text = "\n".join((pg.extract_text() or "") for pg in PdfReader(io.BytesIO(data)).pages)
            scanned = extract_fields(text)
            pdf_no_text = not any(scanned.values())
        except Exception:
            scanned = {}
            pdf_no_text = True
    elif ext in ("jpg", "jpeg", "png", "webp", "bmp"):
        from main import detect_image, looks_like_scanned_document  # lazy: avoid circular import
        try:
            ai_det = detect_image(data, filename)
        except Exception:
            ai_det["explanation"] = "AI detector unavailable."
        try:
            ai_det["document_aware"] = looks_like_scanned_document(data)
        except Exception:
            ai_det["document_aware"] = None

    # Optionally ingest fields typed by the screening officer at the desk.
    declared = {k: v for k, v in (declared or {}).items() if isinstance(v, str) and v.strip()}
    decl_fields = extract_fields(" ".join(declared.values()))

    fields = {**scanned}
    for k, v in decl_fields.items():
        if v and not fields.get(k):
            fields[k] = v

    # ---- Analyze: signals, each one explainable -----------------------------
    reasons = []
    risk = 20  # neutral starting point; stays low when evidence is clean

    aadhaar = fields.get("aadhaar")
    if aadhaar:
        reasons.append(f"Aadhaar present and passes the Verhoeff checksum ({mask(aadhaar)}).")
        risk -= 4
    elif "adhaar" in (doc_type or "").lower() and not aadhaar:
        reasons.append("Aadhaar declared but no checksum-valid number could be read.")
        risk += 28

    pan = fields.get("pan")
    if pan:
        reasons.append(f"PAN validates as a 10-character identity code ({mask(pan)}).")
        risk -= 3
    elif "pan" in (doc_type or "").lower() and not pan:
        reasons.append("PAN declared but the document does not contain a valid PAN structure.")
        risk += 20

    dl = fields.get("driving_licence")
    if dl:
        reasons.append(f"Driving-licence number format validates ({mask(dl)}).")
        risk -= 3
    elif "driving" in (doc_type or "").lower() and not dl:
        reasons.append("Driving licence declared but no licence number could be validated.")
        risk += 14

    voter = fields.get("voter_id")
    if voter:
        reasons.append(f"Voter-ID (EPIC) number validates as 3 letters + 7 digits ({mask(voter)}).")
        risk -= 3
    elif "voter" in (doc_type or "").lower() and not voter:
        reasons.append("Voter ID declared but no valid EPIC (3 letters + 7 digits) was read.")
        risk += 14

    passport = fields.get("passport")
    mrz_valid = fields.get("mrz_valid")
    if passport:
        if mrz_valid is True:
            reasons.append(f"Passport {mask(passport)} passes every MRZ check digit — the "
                           "machine-readable zone is internally consistent.")
            risk -= 6
        elif mrz_valid is False:
            reasons.append(f"Passport {mask(passport)} has an MRZ whose check digits FAIL — "
                           "a very strong tamper signal.")
            risk += 26
        else:
            reasons.append(f"Passport number found ({mask(passport)}) but no valid MRZ was "
                           "read to cross-check it — inspect the zone by eye.")
            risk += 10

    dob = fields.get("dob")
    if dob:
        if dob > _today():
            reasons.append(f"Date of birth {dob} is in the FUTURE on this document.")
            risk += 30
        elif dob.startswith("20") and passport:
            reasons.append("Child DOB on a passport — require guardian linkage.")
            risk += 6

    expiry = (declared.get("expiry_date") or "").strip()
    if expiry and expiry < _today():
        reasons.append(f"Expiry date {expiry} is in the PAST — the document is no longer valid.")
        risk += 22

    if ai_det.get("ai_suspected"):
        reasons.append("Computer-vision scan suggests the document IMAGE is AI-generated or "
                       "edited — synthetic documents are a known forgery vector.")
        risk += 16
    if ai_det.get("document_aware") is True:
        reasons.append("File reads as a scanned paper document (screenshots and selfies do not "
                       "trigger this) — orientation/medium looks right.")
    elif ai_det.get("document_aware") is False and (doc_type or "").lower() not in ("other", ""):
        # A photo of a screen / a re-photographed document is a real-world forgery
        # vector at immigration desks; call it out rather than silently ignoring it.
        reasons.append("The image does not read as a scanned paper document — a photo of a "
                       "screen or re-photographed identity document is a known forgery vector.")
        risk += 8

    if pdf_no_text:
        reasons.append("PDF contains no extractable text layer (scanned or image-only pages) — "
                       "identifier checksums could not run, so treat the number on the paper as "
                       "unverified until a human or OCR reads it.")
        risk += 4

    # ---- Watchlist (hash-based, privacy-preserving) -------------------------
    watched = {e.identifier_hash for e in db.query(WatchlistEntry).all()}
    hits = []
    for key in ("aadhaar", "pan", "driving_licence", "passport", "voter_id", "phone", "dob"):
        val = fields.get(key)
        if val and sha256(val) in watched:
            hits.append({"field": key, "mask": mask(val)})
    if hits:
        joined = "; ".join(f"{h['field']} {h['mask']}" for h in hits)
        reasons.append(f"WATCHLIST HIT — {joined}. Reroute to a supervisory officer.")
        risk += 60

    if ledger_status == "AUTHENTIC":
        reasons.append("The exact file is signed on the nocap provenance ledger — its origin is "
                       "cryptographically authenticated.")
        risk -= 38
    elif ledger_status == "REVOKED":
        reasons.append("The exact file matches a REVOKED ledger signature — treat it as void.")
        risk += 32

    # Evidence coverage: how much of this decision is grounded vs by-eye?
    identified = any(bool(fields.get(k)) for k in
                     ("aadhaar", "pan", "driving_licence", "passport", "voter_id"))
    evidence = sum(bool(v) for v in fields.values() if v) + bool(declared) + len(hits)
    coverage = min(evidence, 8) / 8.0
    confidence = round(min(0.98, 0.45 + coverage * 0.5), 2)
    if risk <= 30 and coverage < 0.4 and not identified:
        reasons.append("No machine-readable fields were extractable and nothing was declared — "
                       "a manual inspection is advised before clearing.")
        risk = 34  # never CLEAR on an empty evidence base

    risk = max(0, min(100, risk))
    verdict = _grade(risk)

    report = {
        "id": uuid.uuid4().hex[:16],
        "file_hash": file_hash,
        "filename": filename or "upload",
        "doc_type": doc_type or "UNKNOWN",
        "checkpoint": checkpoint or "",
        "verdict": verdict,
        "risk_score": risk,
        "confidence": confidence,
        "ledger_status": ledger_status,
        "masked_fields": {k: (mask(v) if isinstance(v, str) else v)
                          for k, v in fields.items()},
        "watchlist_hits": hits,
        "reasons": reasons,
        "ai_detection": {k: ai_det.get(k) for k in
                         ("ran", "ai_suspected", "ai_score", "model", "provider",
                          "explanation", "latency_ms")},
        "latency_ms": int((time.monotonic() - started) * 1000),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }

    db.add(ScreeningReport(
        id=report["id"], file_hash=file_hash, filename=report["filename"],
        doc_type=report["doc_type"], checkpoint=report["checkpoint"],
        verdict=verdict, risk_score=risk, confidence=confidence,
        extracted_fields=json.dumps(report["masked_fields"]),
        signals=json.dumps(reasons),
        ai_detection=json.dumps(report["ai_detection"]),
        ledger_status=ledger_status, screener=screener,
        created_at=report["created_at"],
    ))
    db.commit()
    return report