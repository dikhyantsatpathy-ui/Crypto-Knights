"""
Module 3 — Account / Identity Tampering Detection (SIH26188 "AI-Based Fake
Identity & Document Screening"). For images, runs the visual-forensics suite
from app/forensics.py — ELA (error-level analysis), focus/exposure QA, zone
boxes, and passive liveness cues — and folds in the AI-generation / "photo of
a screen" signals the calling desk already computed, each mapped to an
explainable check {label, ok, detail}. PDFs and unreadable inputs degrade to
honest "not applicable" rows, never to a silent pass.
"""


def tamper_analysis(image_bytes: bytes | None, ai_detection: dict | None = None,
                    document_aware: bool | None = None, doc_type: str = "") -> dict:
    """Run Module 3 for a document.

    Returns {checks, ela, qa, roi, liveness, ai_detection, verdict}. The
    forensics sub-block (`ela`, `qa`, `roi`, `liveness`) is passed through edge
    to the desk's overlay, so the ESL heatmap and zone boxes render on the
    document preview without forensics.py being re-wired anywhere else.
    """
    checks = []
    doc_type = (doc_type or "").strip().lower()
    ai_detection = ai_detection or {"ran": False, "explanation": "No image."}

    if image_bytes is None:
        from forensics import forensics_report
        f0 = forensics_report(b"")  # always returns the "not readable" shape
        return {"checks": [{"label": "ela", "ok": None, "detail": "No image supplied."}],
                "ela": f0["ela"], "qa": f0["qa"], "roi": [], "liveness": [],
                "ai_detection": ai_detection, "verdict": "UNVERIFIED"}

    from forensics import forensics_report

    fr = forensics_report(image_bytes)
    if fr.get("error"):
        return {"checks": [{"label": "image", "ok": None,
                            "detail": f"Image not readable: {fr['error']}"}],
                "ela": None, "qa": None, "roi": [], "liveness": [],
                "ai_detection": ai_detection, "verdict": "UNVERIFIED"}

    ela = fr["ela"] or {}
    qa = fr["qa"] or {}
    roi = fr["roi"] or []
    liveness = fr["liveness"] or []

    # ---- ELA: tampered region lights up ----------------------------------
    if ela.get("status"):
        checks.append({
            "label": "ela",
            "ok": ela["status"] == "LOW",
            "detail": (f"ELA {ela['status']} — {round((ela.get('damage_ratio') or 0) * 100)}% "
                       "of 8x8 blocks deviate from expected re-compression"),
        })
    else:
        checks.append({"label": "ela", "ok": None,
                       "detail": "ELA could not run on this image."})

    # ---- Focus: blur hides tamper artifacts ------------------------------
    if qa.get("blurry"):
        checks.append({"label": "focus", "ok": False,
                       "detail": "Image is soft (Laplacian variance low) — blur can hide "
                                 "re-compression and pixel-borrowing artifacts."})
    else:
        checks.append({"label": "focus", "ok": qa.get("blur_est") is not None,
                       "detail": f"Focus looks acceptable (Blur est {qa.get('blur_est')})."})

    # ---- Passive liveness cues (single frame) ----------------------------
    for sig in liveness:
        if sig.get("level") in ("warn", "danger"):
            checks.append({
                "label": f"liveness-{sig.get('signal', 'cue')}",
                "ok": False if sig.get("level") == "danger" else None,
                "detail": sig.get("note", ""),
            })
    if not any(c["label"].startswith("liveness-") for c in checks):
        checks.append({"label": "liveness", "ok": None,
                       "detail": "Still frame cannot prove aliveness — pair with the "
                                 "webcam capture for a person check."})

    # ---- AI-generation / screen-aware signal -----------------------------
    if ai_detection.get("ai_suspected"):
        checks.append({"label": "ai-generated", "ok": False,
                       "detail": (ai_detection.get("explanation") or
                                  "Vision scan flags the document image as synthetic.")})
    if document_aware is False and doc_type and doc_type != "other":
        checks.append({"label": "medium", "ok": False,
                       "detail": "Image does not read as a scanned paper document — a "
                                 "photo of a screen / re-photographed document is a "
                                 "known forgery vector."})

    # ---- 2D-FFT Spectral Frequency Analysis ------------------------------
    spectral = fr.get("spectral") or {}
    if spectral.get("spectral_anomaly"):
        checks.append({
            "label": "spectral-analysis",
            "ok": False,
            "detail": f"Anomalous high-frequency periodicity (PAPR {spectral.get('papr', 0)}x) — generative grid or screen recapture.",
        })
    elif spectral.get("papr") is not None:
        checks.append({
            "label": "spectral-analysis",
            "ok": True,
            "detail": f"Optical frequency spectrum consistent with natural physical capture (PAPR {spectral.get('papr')}x).",
        })

    # ---- Sensor Noise Consistency (PRNU / Photo Splicing) ----------------
    noise = fr.get("noise_consistency") or {}
    if noise.get("status") == "SUSPECT_PHOTO_SPLICE":
        checks.append({
            "label": "sensor-noise",
            "ok": False,
            "detail": noise.get("detail", "Sensor noise variance disparity indicates photo replacement or splicing."),
        })
    elif noise.get("consistent") is True and noise.get("noise_ratio") is not None:
        checks.append({
            "label": "sensor-noise",
            "ok": True,
            "detail": noise.get("detail", "Uniform sensor noise distribution verified across portrait and substrate."),
        })

    decided = [c for c in checks if c.get("ok") is not None]
    failed = any(c.get("ok") is False for c in decided)
    passed = decided and all(c.get("ok") is True for c in decided)
    verdict = "PASS" if passed else ("FAIL" if failed else "REVIEW")

    return {"checks": checks, "ela": ela, "qa": qa, "roi": roi, "liveness": liveness,
            "ai_detection": ai_detection, "verdict": verdict}