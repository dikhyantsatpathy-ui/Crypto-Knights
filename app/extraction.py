"""
Module 1 — OCR Extraction (SIH26188 "AI-Based Fake Identity & Document
Screening"). One uploaded document -> machine-readable fields:

  pdf   -> pypdf text layer -> extract_fields (identifier regexes + MRZ)
  image -> tesseract OCR (best-effort) + MRZ parse

Everything else joins here too: the officer's typed `declared` map merged over
the scan (declared never overrides machine-read values; it back-fills gaps so
officer typos cannot silently shadow verified fields).

Output is the same zero-storage shape as the rest of the desk: raw text and
photos are read, used, and discarded — only masked identifiers and checksums
move on to Module 2.
"""

# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def extract_document(data: bytes, filename: str = "", doc_type: str = "",
                     declared: dict = None) -> dict:
    """Run the extraction pass over one document.

    Returns a dict the screening desk merges into its report:
      medium     "pdf" | "image" | "unknown"
      fields     normalized identifier fields {pan, dl, passport, ...}
      mrz        parsed MRZ block (passport / visa) or None
      ocr        {ran, engine, reason} metadata
      pdf_no_text made this pass for image-only PDFs
      ai_detection / document_aware: filled by run_screening when the caller
                 already computed them (they live in app/main.py); not rerun here.
    """
    declared = {k: v for k, v in (declared or {}).items()
                if isinstance(v, str) and v.strip()}
    ext = (filename or "").lower().rsplit(".", 1)[-1] if "." in (filename or "") else ""

    from screening import extract_fields

    result = {
        "medium": "unknown",
        "fields": {},
        "mrz": None,
        "ocr": {"ran": False, "reason": "no image"},
        "pdf_no_text": False,
        "ai_detection": {"ran": False, "explanation": "No image."},
        "document_aware": None,
    }

    if ext == "pdf":
        result["medium"] = "pdf"
        text = _pdf_text(data)
        if text:
            result["fields"] = extract_fields(text)
        else:
            result["pdf_no_text"] = True
            result["ocr"] = {"ran": False,
                             "reason": "PDF has no extractable text layer (scan)."}
    elif ext in ("jpg", "jpeg", "png", "webp", "bmp"):
        result["medium"] = "image"
        result.update(_extract_image(data))

    # Merge declared values only into gaps (machine-read values win).
    decl_fields = extract_fields(" ".join(declared.values()))
    for k, v in decl_fields.items():
        if v and not result["fields"].get(k):
            result["fields"][k] = v
    return result


# --------------------------------------------------------------------------- #
# Medium-specific passes
# --------------------------------------------------------------------------- #

def _pdf_text(data: bytes) -> str:
    try:
        import io
        from pypdf import PdfReader
        pages = PdfReader(io.BytesIO(data)).pages
        return "\n".join((pg.extract_text() or "") for pg in pages)
    except Exception:
        return ""


def _extract_image(data: bytes) -> dict:
    """OCR + MRZ over one image. Each subsystem is isolated: a failure in
    one never loses the rest, and unreadable input degrades to honest 'ran:
    False' rather than a hard error."""
    from screening import extract_fields
    from identity import ocr_extract
    from mrz import parse_mrz

    out = {"fields": {}, "mrz": None,
           "ocr": {"ran": False, "reason": "not run"}, "pdf_no_text": False}

    text, ocr_meta = ocr_extract(data)
    out["ocr"] = ocr_meta
    if text:
        out["fields"] = extract_fields(text)

    if text:
        try:
            mrz_res = parse_mrz(text)
            if mrz_res.get("valid"):
                out["mrz"] = _mrz_public(mrz_res)
        except Exception:
            out["mrz"] = None
    return out


def _mrz_public(res: dict) -> dict:
    """Slim MRZ result for the report: format + check-digit outcome + masked
    identifiers. Never the raw MRZ lines (zero-storage rule)."""
    from screening import mask
    checks = res.get("checks") or {}
    pub = {
        "format": res.get("format"),
        "valid": bool(res.get("valid")),
        "document_ck": _check_ok(checks.get("document_number")),
        "dob_ck": _check_ok(checks.get("dob")),
        "expiry_ck": _check_ok(checks.get("expiry")),
        "composite_ck": _check_ok(checks.get("composite")),
    }
    pno = res.get("passport_number")
    if pno:
        pub["passport"] = mask(pno)
    return pub


def _check_ok(ck):
    return ck.get("ok") if isinstance(ck, dict) else None