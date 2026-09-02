"""
Scanned-document-awareness helper.

Tells a plain AI-art detector apart from a *scanned document / text-heavy page*.
This matters because the cloud detectors (Sightengine, Hive, ...) are trained to
separate AI-generated *photos/art* from real *photographs* — they are NOT built
to judge photocopies of paper. If we let them loose on a scanned notice they
misfire (a legible scan reads as "suspicious, low-confidence" and wastes budget).

So we conservatively detect "this looks like a scanned page" and, when we do,
surface a DOCUMENT verdict: tell the user the real trust signal here is the
signature / provenance / OCR, not image-AI analysis.

Heuristics (all conservative, none can raise):
  - "page-like" aspect ratio (a sheet of paper, not a square selfie).
  - mostly-light background (white/cream paper) with dark ink pixels.
  - high foreground "ink density" of small blobs = text characters.
  - low colour variance (monochrome or near-monochrome scans).
We require SEVERAL signals together to fire, so real photos and flat graphics
are not misread as documents.
"""

import io

from ._util import _np, _pil  # lazy numpy / PIL import helpers


def _open_gray(file_bytes: bytes, np):
    Image = _pil()
    if Image is None:
        return None
    if np is None:
        return None
    try:
        return Image.Image.open(io.BytesIO(file_bytes)).convert("L")
    except Exception:
        return None


def looks_like_scanned_document(file_bytes: bytes) -> bool:
    """Conservative boolean: is this image a page/document rather than a photo?"""
    np = _np()
    if np is None or _pil() is None:
        return False
    img = _open_gray(file_bytes, np)
    if img is None or img.width == 0 or img.height == 0:
        return False

    # Downscale for speed, but keep it high enough that thin text glyphs don't get
    # anti-aliased into pale grey (which would hide the ink signal). A 640px-wide
    # cap is plenty for page-shaped layout and stays fast.
    max_w = 640
    if img.width > max_w:
        img = img.resize((max_w, int(img.height * max_w / img.width)))

    w, h = img.size
    ar = w / h

    a = np.asarray(img, dtype=np.uint8)

    # 1) Page-like aspect (portrait ~0.5-0.95, landscape ~1.05-2.0). A square
    #    selfie (0.8-1.25) overlaps portrait, so require more than just aspect.
    page_aspect = 0.62 <= ar <= 2.0
    # Real-world page sheets sit around 0.7-1.41; widen safely but still exclude
    # extreme panoramas. Combine with the "paper" check below.

    hist = np.bincount(a.ravel(), minlength=256).astype(np.float64)
    total = float(a.size)
    if total == 0:
        return False

    # 2) "Paper": a bright, near-uniform background peak.
    #    Fraction of pixels at or above 200 (white-ish).
    white_frac = float(hist[200:].sum()) / total

    # 3) Ink coverage: dark pixels far from the paper white. Sparse notice text
    #    can be <2% of a large page, so keep the floor low.
    ink = float(hist[:170].sum()) / total

    # 4) Colour variance is handled by callers that pass RGB; here on L we use
    #    the width of the histogram around the white peak (low = clean paper).
    #    Compute std of pixels below 250 (exclude the white bulk from noise).
    dark = a[a < 200]
    dark_std = float(np.std(dark)) if dark.size else 0.0

    # Text pages: white background + scattered small dark ink.
    papery = white_frac >= 0.45
    inky = 0.003 <= ink <= 0.55
    ink_scatter = dark_std >= 25.0   # varied ink tone, not one flat dark block
    not_photo_flat = ar < 1.9        # avoid squashing wide banners into docs

    # Require the page shape AND a strong paper/ink signature. A photograph with
    # paper in it (a hand holding a document) usually has one dominant irregular
    # bright region, not page-shaped text coverage, so it won't pass all gates.
    score = sum(bool(x) for x in (page_aspect, papery, inky, ink_scatter))
    return score >= 3 and papery and inky and not_photo_flat


def document_verdict(filename: str = "") -> dict:
    """Return the normalized 'this is a document' result."""

    name = (filename or "scanned notice").rsplit("/", 1)[-1]
    return {
        "ran": False,
        "ai_suspected": False,
        "ai_score": 0,
        "model": "document-aware pre-check",
        "provider": "document",
        "explanation": (
            f"'{name}' reads as a scanned document / text page rather than a "
            "photograph. Cloud AI-art detectors are built for photos and would "
            "misfire here, so the authenticity of this notice rests on the "
            "cryptographic signature and provenance-chain verification — not on "
            "image-AI analysis. Look for the signature/ledger verdict on this card."
        ),
        "latency_ms": 0,
        "raw": {"document_like": True},
    }