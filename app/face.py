"""
Module 4 — Face Verification (SIH26188 "AI-Based Fake Identity & Document
Screening"). Closes "valid document, wrong person": compare the face in the
document against the holder's live capture.

The document-side face is a face ROI cropped from the document image (Module
3's zone boxes). The live capture is a webcam frame uploaded at the desk.
Matches the face_match.compare_faces contract: {score, match (True|False|None),
method, detail}. `match=None` means "inconclusive — confirm by eye"; the desk
never treats a low-signal comparison as a pass.
"""


def face_verification(document_bytes: bytes | None = None,
                      live_frame: bytes | None = None,
                      doc_type: str = "") -> dict:
    """Run Module 4.

    Returns {score, match, method, detail, checks}. doc_type is advisory —
    when a document portrait is present, a face ROI is cropped from the
    document image. Missing live frame / missing document face degrade to an
    honest inconclusive row rather than a guessed verdict.
    """
    from face_match import compare_faces
    result = {
        "score": 0,
        "match": None,
        "method": "unavailable",
        "detail": "No live capture supplied — face verification skipped.",
        "checks": [
            {"label": "face-match", "ok": None,
             "detail": "No live frame was captured at the desk."},
        ],
        "verdict": "UNVERIFIED",
    }

    if live_frame is None:
        return result

    doc_face_b64 = _document_face_b64(document_bytes)
    if doc_face_b64 is None:
        result["detail"] = "No document-side face found (no face ROI)."
        result["checks"][0]["detail"] = result["detail"]
        return result

    try:
        fm = compare_faces(doc_face_b64, live_frame)
    except Exception as exc:
        result["detail"] = f"Face comparison failed to run: {exc}"
        result["checks"][0]["detail"] = result["detail"]
        return result

    result.update({k: fm.get(k) for k in ("score", "match", "method", "detail")})
    result["checks"] = [{
        "label": "face-match",
        "ok": fm.get("match"),
        "detail": (f"Document portrait vs live capture "
                   f"({fm.get('method')}, score {fm.get('score')}): {fm.get('detail')}"),
    }]
    result["verdict"] = ("PASS" if fm.get("match") is True else
                         ("FAIL" if fm.get("match") is False else "REVIEW"))
    return result


def _document_face_b64(document_bytes):
    """Document-side face: crop the face ROI (if any) out of the document
    image. Returns base64 PNG or None."""
    if document_bytes is None:
        return None
    try:
        from forensics import roi_boxes
        boxes = roi_boxes(document_bytes)
        face = next((b for b in boxes if b.get("label") == "face"), None)
        if not face:
            return None
        import base64
        import io
        from PIL import Image
        img = Image.open(io.BytesIO(document_bytes)).convert("RGB")
        w, h = img.size
        x0 = int(face["x"] * w)
        y0 = int(face["y"] * h)
        x1 = int((face["x"] + face["w"]) * w)
        y1 = int((face["y"] + face["h"]) * h)
        crop = img.crop((max(x0, 0), max(y0, 0), min(x1, w), min(y1, h)))
        out = io.BytesIO()
        crop.save(out, format="PNG")
        return base64.b64encode(out.getvalue()).decode("ascii")
    except Exception:
        return None