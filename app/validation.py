"""
Module 2 — Document Validation (SIH26188 "AI-Based Fake Identity & Document
Screening"). After Module 1 extracted the identifiers, this pass proves the
document as its own evidence: deterministic format + checksum rules per
document type, expiry sanity, MRZ check digits, and the hash-only watchlist
cross-check.

Every check is explainable: {label, ok (True|False|None), detail}. `ok=None`
means "not verifiable here — inspect by eye", never a silent pass. This is the
same contract build_identity_report used, folded into the MHA screening desk.
"""

VALIDATORS = {
    "pan": ("verify_pan", "PAN"),
    "driving_licence": ("verify_dl", "Driving licence"),
    "rc": ("verify_rc", "RC"),
    "voter_id": ("verify_epic", "Voter ID (EPIC)"),
    "passport": ("verify_passport", "Passport"),
    "visa": ("verify_visa", "Visa"),
}

# doc_type -> screening field key that carries the number
_FIELD_FOR = {
    "pan": "pan",
    "driving_licence": "driving_licence",
    "rc": "driving_licence",
    "voter_id": "voter_id",
    "passport": "passport",
    "visa": "passport",
}


def validate_document(
    doc_type: str,
    fields: dict,
    declared: dict | None = None,
    mrz_text: str = "",
    watchlist_hits: list | None = None,
) -> dict:
    """Run Module 2 for a document type.

    Returns {checks, verdict, watchlist_hits}. declared is the officer-typed
    map so a none-found-but-declared document flips to REVIEW instead of staying
    silently unchecked. mrz_text feeds the passport path; the extractor already
    validated MRZ check digits, so that outcome folds in via fields["mrz_valid"]
    when no MRZ text was handed to this module. watchlist_hits (already computed
    by the caller) folds the hash-only cross-check into the checks so a single
    module carries the whole verdict.
    """
    from identity import (verify_pan, verify_dl, verify_rc, verify_epic,
                          verify_passport, verify_visa, serial_plausibility)

    declared = declared or {}
    doc_type = (doc_type or "").strip().lower()
    vfn = VALIDATORS.get(doc_type)
    checks = []

    key = _FIELD_FOR.get(doc_type)
    number = (fields.get(key) if key else None)

    if not number and doc_type and doc_type != "other":
        checks = [{"label": "structure", "ok": None,
                   "detail": "No machine-readable number was extracted — declare it "
                             "or (with tesseract installed) re-photo the document."}]
    elif vfn:
        fn = {"verify_pan": verify_pan, "verify_dl": verify_dl,
              "verify_rc": verify_rc, "verify_epic": verify_epic,
              "verify_passport": verify_passport,
              "verify_visa": verify_visa}[vfn[0]]
        if doc_type in ("passport", "visa"):
            checks = fn(number, mrz_text or "")
            # Raw MRZ lines are never retained (zero-storage); the desk's
            # extractor already validated their check digits, so fold that
            # outcome in when no MRZ text was handed to this module.
            if not mrz_text and fields.get("mrz_valid") is not None:
                checks.append({
                    "label": "mrz-check-digits",
                    "ok": fields["mrz_valid"],
                    "detail": "ICAO 9303 passport/DOB/expiry check digits "
                              "verified by the extractor from the MRZ",
                })
        else:
            checks = fn(number)
        for c in checks:
            c.setdefault("detail", vfn[1])

    elif doc_type in ("other", ""):
        checks = [{"label": "type", "ok": None,
                   "detail": "Unspecified document type — validation limited to "
                             "declared fields and watchlist."}]

    # ---- Feature 3: Serial-range plausibility check -------------------------
    if number and doc_type not in ("other", ""):
        dob = fields.get("dob")
        plaus_checks = serial_plausibility(doc_type, number, dob)
        checks.extend(plaus_checks)


    # ---- Expiry sanity (driving licence, passports, visas) ----------------
    exp = (declared.get("expiry_date") or fields.get("expiry") or "").strip()
    from screening import _parse_date, _today
    exp_parsed = _parse_date(exp)
    if exp_parsed:
        if exp_parsed < tuple(int(x) for x in _today().split("-")):
            checks.append({"label": "expiry", "ok": False,
                           "detail": f"Expiry {exp} is in the PAST — document is "
                                     f"no longer valid."})
        else:
            checks.append({"label": "expiry", "ok": True,
                           "detail": f"Expiry {exp} is in the future."})
    elif doc_type in ("driving_licence", "passport") and exp:
        checks.append({"label": "expiry", "ok": None,
                       "detail": f"Expiry '{exp}' unparseable — verify by eye."})

    # ---- Watchlist (hash-only, privacy-preserving) -------------------------
    # Absence from the watchlist is the GOOD outcome: identifiers found on the
    # watchlist are ALWAYS flagged to a supervisor regardless of checksum.
    hits = watchlist_hits or []
    if hits:
        joined = "; ".join(f"{h['field']} {h['mask']}" for h in hits)
        checks.append({"label": "watchlist", "ok": False,
                       "detail": f"WATCHLIST HIT — {joined}. Reroute to a "
                                 f"supervisory officer."})

    # ---- Verdict from checks ----------------------------------------------
    decided = [c for c in checks if c.get("ok") is not None]
    failed = [c for c in decided if c.get("ok") is False]
    passed = [c for c in decided if c.get("ok") is True]
    if failed and not passed:
        verdict = "FAIL"
    elif passed and not failed:
        verdict = "PASS"
    elif decided:
        verdict = "REVIEW"
    else:
        verdict = "UNVERIFIED"

    return {"checks": checks, "verdict": verdict, "watchlist_hits": hits}