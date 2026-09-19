"""
Face match: QR portrait vs live selfie (closes "valid card, wrong person").

The Aadhaar offline-XML payload can carry the holder's portrait (base64 JPEG
in the `photo` attribute); the liveness desk already captures a selfie. This
module compares the two and returns a conservative 3-state verdict:

    match True   — near-duplicate (same capture pipeline / photocopy)
    match False  — clearly different people
    match None   — inconclusive (no portrait, undecodable bytes, middle band)

Two engines, best available wins:
  1. An ONNX face-embedding model when FACE_EMBED_MODEL points at an .onnx
     file and onnxruntime imports (cosine similarity on L2-normalized
     embeddings; >= 0.60 same, <= 0.40 different, between inconclusive).
  2. Otherwise a whole-image perceptual dHash via Pillow — Pillow already
     ships with the app for QR decoding, so this works on Vercel TODAY
     (Hamming distance <= 8 same, >= 20 different, between inconclusive).

dHash is coarse (a card portrait and a selfie differ in background, lighting,
crop), so the middle band is wide ON PURPOSE and every verdict names its
method. Confirm by eye; point FACE_EMBED_MODEL at an ArcFace/FaceNet-style
graph for production use.
"""

import base64
import io
import os

_DHASH_SAME = 8
_DHASH_DIFF = 20
_EMB_SAME = 0.60
_EMB_DIFF = 0.40

_embed_session = None
_embed_failed = False


def _pil():
    try:
        from PIL import Image
        return Image
    except Exception:
        return None


def _coerce_image_bytes(data) -> bytes | None:
    """Accept raw image bytes OR a base64 string (the QR `photo` attribute
    form). Returns decodable image bytes or None."""
    if not data:
        return None
    if isinstance(data, str):
        data = data.strip()
        try:
            data = base64.b64decode(data)
        except Exception:
            return None
    if not isinstance(data, (bytes, bytearray)) or len(data) < 64:
        return None
    return bytes(data)


def _load_rgb(data: bytes):
    Image = _pil()
    if Image is None:
        return None
    try:
        with Image.open(io.BytesIO(data)) as im:
            return im.convert("RGB")
    except Exception:
        return None


def dhash(image) -> int | None:
    """64-bit difference hash: 9x8 grayscale, one bit per horizontal step."""
    try:
        small = image.convert("L").resize((9, 8))
        px = list(small.tobytes())  # raw 'L' pixels — no deprecated getdata
        bits = 0
        for y in range(8):
            row = y * 9
            for x in range(8):
                bits = (bits << 1) | (1 if px[row + x] > px[row + x + 1] else 0)
        return bits
    except Exception:
        return None


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _embed_image(image):
    """ONNX embedding path. Returns an L2-normalized vector or None (model
    missing/unloadable -> caller falls back to dHash, never crashes)."""
    global _embed_session, _embed_failed
    if _embed_failed:
        return None
    model_path = os.getenv("FACE_EMBED_MODEL", "")
    if not model_path or not os.path.exists(model_path):
        return None
    try:
        import numpy as np
        import onnxruntime as ort
        if _embed_session is None:
            _embed_session = ort.InferenceSession(
                model_path, providers=["CPUExecutionProvider"])
        sess = _embed_session
        inp = sess.get_inputs()[0]
        shape = inp.shape
        h = int(shape[2]) if len(shape) > 2 and isinstance(shape[2], int) else 112
        w = int(shape[3]) if len(shape) > 3 and isinstance(shape[3], int) else 112
        arr = np.asarray(image.resize((w, h)), dtype=np.float32) / 255.0
        arr = arr.transpose(2, 0, 1)[None, ...]
        vec = np.asarray(sess.run(None, {inp.name: arr})[0]).reshape(-1)
        n = float((vec ** 2).sum() ** 0.5)
        return vec / n if n > 0 else None
    except Exception:
        _embed_failed = True
        return None


def compare_faces(qr_photo, selfie) -> dict:
    """Compare a QR portrait against a selfie. Inputs may be raw bytes or
    base64 strings. Never raises; inconclusive inputs yield match None."""
    qr_bytes = _coerce_image_bytes(qr_photo)
    sl_bytes = _coerce_image_bytes(selfie)
    if qr_bytes is None or sl_bytes is None:
        return {"score": 0, "match": None, "method": "unavailable",
                "detail": "Need a QR portrait and a readable selfie image."}
    qr_img = _load_rgb(qr_bytes)
    sl_img = _load_rgb(sl_bytes)
    if qr_img is None or sl_img is None:
        return {"score": 0, "match": None, "method": "unavailable",
                "detail": "One of the images could not be decoded."}

    emb_a, emb_b = _embed_image(qr_img), _embed_image(sl_img)
    if emb_a is not None and emb_b is not None:
        import numpy as np
        sim = float(np.dot(emb_a, emb_b))
        score = int(round(max(0.0, min(1.0, (sim + 1.0) / 2.0)) * 100))
        match = True if sim >= _EMB_SAME else (False if sim <= _EMB_DIFF else None)
        verdict = "same person" if match is True else ("different person" if match is False
                                                       else "inconclusive — confirm by eye")
        return {"score": score, "match": match, "method": "onnx-embedding",
                "detail": f"Face-embedding cosine {sim:.2f}: {verdict}."}

    ha, hb = dhash(qr_img), dhash(sl_img)
    if ha is None or hb is None:
        return {"score": 0, "match": None, "method": "unavailable",
                "detail": "Perceptual hash failed on one of the images."}
    dist = _hamming(ha, hb)
    score = int(round((1.0 - dist / 64.0) * 100))
    match = True if dist <= _DHASH_SAME else (False if dist >= _DHASH_DIFF else None)
    verdict = ("near-duplicate portraits" if match is True
               else ("clearly different portraits" if match is False
                     else "inconclusive — confirm by eye"))
    return {"score": score, "match": match, "method": "phash-dhash",
            "detail": f"Perceptual-hash distance {dist}/64 ({verdict}). Coarse "
                      f"whole-image comparison — set FACE_EMBED_MODEL for production."}


def face_match_capabilities() -> dict:
    """Backend status for /api/identity/meta."""
    Image = _pil()
    onnx = bool(os.getenv("FACE_EMBED_MODEL", "")) and os.path.exists(
        os.getenv("FACE_EMBED_MODEL", ""))
    return {"available": Image is not None,
            "method": "onnx-embedding" if (Image is not None and onnx) else (
                "phash-dhash" if Image is not None else "none"),
            "onnx_configured": onnx}
