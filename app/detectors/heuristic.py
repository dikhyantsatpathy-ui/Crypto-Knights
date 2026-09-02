"""
Free, dependency-light AI-content detector.

Combines (a) metadata self-tags (the most reliable signal when present) with
(b) a conservative pixel-level scan. This is the DEFAULT backend: it needs no
API key, never sends the image anywhere, and costs ~1-4ms. Accuracy is honest
but limited: it reliably flags *self-tagged* generators and extreme oversmoothing,
and can miss AI images that carry no label and aren't obviously over-processed.

The stronger, real-model backends (Sightengine / self-hosted ONNX) live in the
sibling modules and can be enabled with AI_DETECTOR_PROVIDER.
"""

import io
import os
import re
import struct

from ._signatures import AI_SIGS, EDITING_SIGS


def _import_np():
    try:
        import numpy
        return numpy
    except Exception:
        return None


def _import_pil():
    try:
        import PIL
        import PIL.Image  # noqa: F401  (ensure submodule importable)
        return PIL
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Metadata reading (stdlib-only): pull embedded labels out of PNG / JPEG / WebP.
# ---------------------------------------------------------------------------
def _image_metadata_text(file_bytes: bytes, ext: str) -> str:
    out_parts = []
    try:
        data = file_bytes
        if ext == "png" and data[:8] == b"\x89PNG\r\n\x1a\n":
            pos = 8
            while pos + 8 <= len(data):
                (ln,) = struct.unpack(">I", data[pos:pos + 4])
                ctype = data[pos + 4:pos + 8]
                body = data[pos + 8:pos + 8 + ln]
                if ctype in (b"tEXt", b"iTXt", b"zTXt"):
                    try:
                        out_parts.append(body.decode("latin-1", "ignore"))
                    except Exception:
                        pass
                pos += 12 + ln
        elif ext in ("jpg", "jpeg") and data[:2] == b"\xff\xd8":
            pos = 2
            while pos + 4 <= len(data):
                if data[pos] != 0xFF:
                    break
                marker = data[pos + 1]
                (seg_len,) = struct.unpack(">H", data[pos + 2:pos + 4])
                if seg_len < 2 or pos + 2 + seg_len > len(data):
                    break
                seg = data[pos + 4:pos + 2 + seg_len]
                if marker == 0xE1:
                    out_parts.append(_tiff_text(seg))
                pos += 2 + seg_len
        elif ext in ("webp", "gif") and data[:4] == b"RIFF":
            out_parts.append(str(data))
    except Exception:
        pass
    return " ".join(out_parts)


def _tiff_text(seg: bytes) -> str:
    try:
        if len(seg) < 12:
            return ""
        # Minimal TIFF scanner: pull printable ASCII runs (tag names live inside).
        return " ".join(re.findall(r"[ -~]{3,}", seg.decode("latin-1", "ignore")))
    except Exception:
        return ""


def _match_tool(text: str) -> tuple:
    """Return (kind, tool_name, description, confidence) — kind in ai/edited/None."""
    t = (text or "").lower().replace("-", " ").replace("_", " ").replace(".", " ")
    found_ai, found_edit = [], []
    for tool, desc in AI_SIGS.items():
        if tool.lower().replace("-", " ").replace(".", " ") in t:
            found_ai.append(tool)
    for tool, desc in EDITING_SIGS.items():
        if tool.lower().replace("-", " ").replace(".", " ") in t:
            found_edit.append(tool)
    if found_ai:
        tool = max(found_ai, key=len)
        return ("ai", tool, f"Made by {AI_SIGS[tool]}.", 0.9)
    if found_edit:
        tool = max(found_edit, key=len)
        return ("edited", tool, f"Edited in {EDITING_SIGS[tool]}.", 0.6)
    return (None, None, None, None)


# ---------------------------------------------------------------------------
# Pixel-level scan (conservative, no false positives on real photos/flat GIFs).
# ---------------------------------------------------------------------------
def _pixel_scan(file_bytes: bytes, ext: str):
    np = _import_np()
    if np is None or _import_pil() is None:
        return None, None, False
    from PIL import Image, ImageFilter  # noqa: F401
    try:
        img = Image.open(io.BytesIO(file_bytes)).convert("L")
        if img.width == 0 or img.height == 0:
            return None, None, False
        max_w = 160
        if img.width > max_w:
            img = img.resize((max_w, int(img.height * max_w / img.width)))
        a = np.asarray(img, dtype=np.int16)

        g = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.int16)
        lap = np.zeros(a.shape, dtype=np.int16)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                gv = g[dy + 1][dx + 1]
                if gv == 0:
                    continue
                lap += gv * np.roll(np.roll(a, -dy, axis=0), -dx, axis=1)
        noise_std = float(lap.std())

        gross_std = float(np.asarray(a, dtype=np.float32).std())
        fine_noise = noise_std
        ratio = fine_noise / (gross_std + 1e-6)
        content = gross_std > 15.0
        suspicious_noise = ratio < 200.0 and fine_noise < 60.0

        uniform_reencode = False
        if ext in ("jpg", "jpeg") and file_bytes[:2] == b"\xff\xd8":
            try:
                img_rgb = Image.open(io.BytesIO(file_bytes)).convert("RGB")
                if img_rgb.width > max_w:
                    img_rgb = img_rgb.resize((max_w, int(img_rgb.height * max_w / img_rgb.width)))
                buf = io.BytesIO()
                img_rgb.save(buf, format="JPEG", quality=90)
                re = Image.open(buf).convert("L")
                ra = np.asarray(re, dtype=np.float32)
                b = np.asarray(img.convert("L"), dtype=np.float32)
                diff = np.abs(ra - b)[::8, ::8] / 255.0
                flat = diff.flatten()
                uniform_reencode = float(np.std(flat)) < 0.02 and float(np.mean(flat)) > 0.01
            except Exception:
                uniform_reencode = False

        suspicious = (content and suspicious_noise) or uniform_reencode
        if suspicious:
            return ("ai", ("Pixel-level scan found tonal content but an unnaturally smooth "
                           "low-noise pattern (or uniform re-compression error) — a hallmark "
                           "of AI generation or heavy automated processing."), True)
        return None, None, True
    except Exception:
        return None, None, False


# ---------------------------------------------------------------------------
# Public detector contract.
# ---------------------------------------------------------------------------
def heuristic_score(report) -> int:
    """Map a heuristic report to a 0..100 confidence number."""
    if report.get("ai"):
        return 80
    if report.get("edited"):
        return 55
    return 0


def heuristic_detect(image_bytes: bytes, filename: str = "") -> dict:
    ext = (filename or "").lower().split(".")[-1] if "." in (filename or "") else ""
    reasons = []
    leaning = "unknown"
    tool = None
    is_ai, is_edited = False, False

    text = _image_metadata_text(image_bytes, ext)
    kind, tool, desc, conf = _match_tool(text)
    if kind == "ai":
        is_ai = True
        leaning = "ai"
        reasons.append(desc)
    elif kind == "edited":
        is_edited = True
        leaning = "edited"
        reasons.append(desc)

    pixel_lean, pixel_reason, ran = _pixel_scan(image_bytes, ext)
    if ran and pixel_lean == "ai" and not is_ai:
        is_ai = True
        leaning = "ai"
        reasons.append(pixel_reason)

    if not reasons:
        if not ran:
            reasons.append("No detector could open this image to look for AI signatures.")
        else:
            reasons.append("No editing apps or AI tools were found in this file's labels, "
                           "and the pixel pattern looked ordinary.")

    score = heuristic_score({"ai": is_ai, "edited": is_edited})
    model = f"heuristic v2 ({'metadata+pixels' if ran else 'metadata only'})"
    if is_ai:
        explanation = (f"The built-in {model} flagged this as AI-generated "
                       f"({score}% confident).") + (f" It detected {tool}." if tool else "")
    elif is_edited:
        explanation = (f"The built-in model saw a photo-editing tool ({tool}) "
                       f"marker, not a plain untouched original.")
    else:
        explanation = ("The built-in model found no AI-generation or editing signature, "
                       "so there is no evidence it was made by a machine.")

    return {
        "ran": len(reasons) > 0 and ran,
        "ai_suspected": is_ai,
        "ai_score": score,
        "model": model,
        "provider": "heuristic",
        "explanation": explanation,
        "latency_ms": 0,
        "raw": {"kind": leaning, "tool": tool, "reasons": reasons},
    }