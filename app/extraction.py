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

# Declared keys are keyed by purpose, not by free text. Generic keys always
# belong to the selected document type; unrelated typed keys (for example, an
# EPIC key supplied during passport screening) are ignored so one form cannot
# populate another document's identifier field.
_TARGET_FIELD_FOR = {
    "passport": "passport",
    "visa": "passport",
    "pan": "pan",
    "driving_licence": "driving_licence",
    "voter_id": "voter_id",
    "rc": "driving_licence",
}
_GENERIC_DECL_KEYS = {"document_number", "doc_number", "number", "id", "declared"}


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
        text, img_bytes = _pdf_text_or_image(data)
        if text:
            result["fields"] = extract_fields(text)
        elif img_bytes:
            img_res = _extract_image(img_bytes)
            result["fields"] = img_res.get("fields", {})
            result["mrz"] = img_res.get("mrz")
            result["ocr"] = img_res.get("ocr", {"ran": True, "engine": "pdf-embedded-ocr"})
            result["pdf_no_text"] = False
        else:
            result["pdf_no_text"] = True
            result["ocr"] = {"ran": False,
                             "reason": "PDF has no extractable text layer (scan)."}
    elif ext in ("jpg", "jpeg", "png", "webp", "bmp"):
        result["medium"] = "image"
        result.update(_extract_image(data))

    # Merge declared values only into gaps (machine-read values win).
    # Scope parsing to the selected document type: only generic identifier
    # keys or keys naming this document are considered. Unknown/unspecified
    # types retain the legacy behavior of scanning all declared values.
    doc_key = (doc_type or "").lower().strip()
    target = _TARGET_FIELD_FOR.get(doc_key)
    selected = []
    for k, v in declared.items():
        key = (k or "").lower().strip()
        if not doc_key or target is None:
            selected.append(v)
        elif (key in _GENERIC_DECL_KEYS or doc_key in key or
                (target and target in key)):
            selected.append(v)
    decl_text = " ".join(v for v in selected if isinstance(v, str))
    if not decl_text:
        decl_text = " ".join(v for v in declared.values()
                             if isinstance(v, str))
    decl_fields = extract_fields(decl_text)
    for k, v in decl_fields.items():
        if v and not result["fields"].get(k):
            result["fields"][k] = v
    return result


# --------------------------------------------------------------------------- #
# Medium-specific passes
# --------------------------------------------------------------------------- #

def _pdf_text_or_image(data: bytes) -> tuple[str, bytes | None]:
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        text = "\n".join((pg.extract_text() or "") for pg in reader.pages)
        if text.strip():
            return text, None
        if reader.pages:
            p0 = reader.pages[0]
            if getattr(p0, "images", None) and len(p0.images) > 0:
                first_img = p0.images[0]
                return "", getattr(first_img, "data", None)
    except Exception:
        pass
    return "", None


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
        try:
            mrz_res = parse_mrz(text)
            if mrz_res.get("valid"):
                out["mrz"] = _mrz_public(mrz_res)
                # Enrich fields with verified MRZ data
                if mrz_res.get("passport_number") and not out["fields"].get("passport"):
                    out["fields"]["passport"] = mrz_res["passport_number"]
                if mrz_res.get("dob") and not out["fields"].get("dob"):
                    out["fields"]["dob"] = mrz_res["dob"]
                if mrz_res.get("expiry") and not out["fields"].get("expiry"):
                    out["fields"]["expiry"] = mrz_res["expiry"]
                mrz_full_name = f"{mrz_res.get('surname', '')} {mrz_res.get('given_names', '')}".strip()
                if mrz_full_name and not out["fields"].get("mrz_name"):
                    out["fields"]["mrz_name"] = mrz_full_name
                out["fields"]["mrz_valid"] = True
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