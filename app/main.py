"""
No cap 2.0 - Enterprise Provenance Engine
Organized into strict, human-readable columns for easy debugging.
"""

import os
import sys

# Resolve where static assets (index.html, main.js) live regardless of the
# process working directory (serverless CWD differs from local runs).
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Ensure the sibling `app/` directory is importable so `from detectors import ...`
# resolves whether this file is run as `python app/main.py`, as a package, or
# behind the Vercel entrypoint (which may set a different CWD).
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

import base64
import hashlib
import hmac
import io
import json
import re
import threading
import time
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import List

from dotenv import load_dotenv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, Request, File, Form, HTTPException, UploadFile, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool
# Media Trapping & Blockchain Dependencies
from sqlalchemy import create_engine, Column, String, Integer, Boolean, LargeBinary, Text, Float, text, func, event
from sqlalchemy import update as sa_update

from sqlalchemy.orm import declarative_base, sessionmaker, defer
from sqlalchemy.exc import IntegrityError

from sqlalchemy.dialects.postgresql import insert as pg_insert
# --- SECURITY DEPENDENCIES ---
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

# AI-content-detection orchestrator (imported once at startup; heavy backends
# like onnxruntime / the cloud SDK are loaded lazily inside the package, so this
# never slows down cold starts for the default heuristic path).
from screening import run_screening
# Passport/Visa MRZ / Driving-Licence / PAN / Voter-ID validation lives in
# identity.py and feeds the screening desk's Module 2 (document validation)
# through app/validation.py. Emits explainable checks, stores zero raw bytes.
# ============================================================================
# AI-content detection layer
# 6 providers (free heuristic, Sightengine cloud, self-hosted ONNX) folded into
# one module so the backend is exactly two source files: main.py + screening.py.
# Result contract + design notes are kept inline so this section stays self-documenting.
# ============================================================================
# ----------------------------------------------------------------------------
# section: app/detectors/_util.py (inlined)
# ----------------------------------------------------------------------------
"""Shared lazy third-party imports used across the detector package."""

_imports = {}


def _np():
    """Return the numpy module, or None if unavailable (lazy, cached)."""
    if "np" not in _imports:
        try:
            import numpy
            _imports["np"] = numpy
        except Exception:
            _imports["np"] = None
    return _imports["np"]


def _pil():
    """Return the PIL module, or None if unavailable (lazy, cached)."""
    if "pil" not in _imports:
        try:
            import PIL.Image
            _imports["pil"] = PIL
        except Exception:
            _imports["pil"] = None
    return _imports["pil"]

# ----------------------------------------------------------------------------
# section: app/detectors/_signatures.py (inlined)
# ----------------------------------------------------------------------------
"""
Known AI-generator and photo-editor self-tags.

When an AI tool (Midjourney, Stable Diffusion, Firefly, Topaz, ...) or a photo
editor (Photoshop, Snapseed, VSCO, ...) writes an image, it often leaves a small
label inside the file (EXIF / PNG-text / XMP). We match those labels to explain,
in plain language, WHY a file looks machine-made or edited.

This is a signal, never proof: a stripped file or a real camera photo carries
none of these tags, so absence does not mean "human-made".
"""


# ----------------------------------------------------------------------------
# section: app/detectors/document_aware.py (inlined)
# ----------------------------------------------------------------------------
"""
Scanned-document-awareness helper.

Tells a plain AI-art detector apart from a *scanned document / text-heavy page*.
This matters because the cloud detectors (Sightengine, Hive, ...) are trained to
separate AI-generated *photos/art* from real *photographs* â€” they are NOT built
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
            "cryptographic signature and provenance-chain verification â€” not on "
            "image-AI analysis. Look for the signature/ledger verdict on this card."
        ),
        "latency_ms": 0,
        "raw": {"document_like": True},
    }

# ----------------------------------------------------------------------------
# section: app/detectors/heuristic.py (inlined)
# ----------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Pixel-level scan (conservative, no false positives on real photos/flat GIFs).
# ---------------------------------------------------------------------------
def _pixel_scan(file_bytes: bytes, ext: str):
    np = _import_np()
    if np is None or _import_pil() is None:
        return None, None, False
    from PIL import Image
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
                           "low-noise pattern (or uniform re-compression error) â€” a hallmark "
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

# ----------------------------------------------------------------------------
# section: app/detectors/provider_sightengine.py (inlined)
# ----------------------------------------------------------------------------
"""
Sightengine AI-detection backend (cloud, trained model).

Recommended real-model backend for the judge-facing demo: a hosted, pre-trained
neural classifier returns a genuine confidence score (`type.ai_generated`), and
names which generator(s) built the image. Fast (<500ms typical), never needs a
GPU of our own, but DOES send the image bytes to a third party â€” only enable it
if that is acceptable for your deployment.

Activation (set in Vercel env / local .env):
    AI_DETECTOR_PROVIDER = sightengine
    AI_DETECTOR_KEY      = your Sightengine api_user:api_secret  (user:secret)

    If your key is a bare single token (no colon), it is taken as the `api_user`
    and the `api_secret` is read from AI_DETECTOR_SECRET. Prefer the documented
    `api_user:api_secret` form from https://sightengine.com/dashboard.

    AI_DETECTOR_MODELS    = model(s) to run (default `genai` = AI-image only).
    AI_DETECTOR_TIMEOUT_MS= per-call budget (default 2500).

Docs: https://sightengine.com/docs/ai-generated-image-detection

FREE-TIER / COST: 2,000 ops/month capped 500/day; each `genai` check consumes
`request.operations` operations (typically 1-5 depending on the model combo).
We parse that and store it so the UI can show an honest "uses remaining".
"""

BASE = os.getenv("AI_DETECTOR_ENDPOINT") or "https://api.sightengine.com"
CHECK_URL = f"{BASE}/1.0/check.json"
TIMEOUT_MS = int(os.getenv("AI_DETECTOR_TIMEOUT_MS", "2500"))
# Default to the cheap single genai model. Add more comma-separated if desired
# (each extra model raises request.operations).
MODELS = os.getenv("AI_DETECTOR_MODELS", "genai")


def _credential() -> tuple:
    """Return (api_user, api_secret) from env, handling both key forms."""
    key = (os.getenv("AI_DETECTOR_KEY") or "").strip()
    secret = (os.getenv("AI_DETECTOR_SECRET") or "").strip()
    if key:
        if ":" in key:
            user, _, ser = key.partition(":")
            return user, ser
        # Single-token form: treat the token as the user id, use AI_DETECTOR_SECRET.
        if secret:
            return key, secret
        return key, ""
    return "", "" if not secret else ("", secret)


def _ready() -> bool:
    user, secret = _credential()
    return bool(user and secret)


def sightengine_score(payload: dict) -> int:
    """Map Sightengine's `type.ai_generated` (0..1) to a 0..100 int."""
    try:
        ai = float((payload.get("type") or {}).get("ai_generated", 0) or 0)
        return int(round(max(0.0, min(100.0, ai * 100.0))))
    except Exception:
        return 0


def sightengine_used(payload: dict) -> int:
    """How many Sightengine operations this last request consumed."""
    try:
        return int((payload.get("request") or {}).get("operations", 0))
    except Exception:
        return 0


def sightengine_detect(image_bytes: bytes, filename: str = "") -> dict:
    if not _ready():
        return {
            "ran": False, "ai_suspected": False, "ai_score": 0,
            "model": "Sightengine", "provider": "sightengine",
            "explanation": ("Sightengine was selected but no valid key pair was "
                            "configured, so the free built-in detector ran instead."),
            "latency_ms": 0, "raw": None,
        }
    # Downscale server-side so the upload fits the free-tier/quality budget fast.
    try:
        from PIL import Image
        import io as _io
        img = Image.open(_io.BytesIO(image_bytes)).convert("RGB")
        max_w = 1024
        if img.width > max_w:
            img = img.resize((max_w, int(img.height * max_w / img.width)))
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=88)
        data_bytes = buf.getvalue()
    except Exception:
        data_bytes = image_bytes

    start = time.perf_counter()
    try:
        files = {"media": ("img.jpg", data_bytes, "image/jpeg")}
        user, secret = _credential()
        params = {
            "models": MODELS,
            "api_user": user,
            "api_secret": secret,
        }
        import requests
        resp = requests.post(CHECK_URL, data=params, files=files,
                             timeout=TIMEOUT_MS / 1000.0)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("status") != "success":
            raise ValueError(payload.get("error") or "sightengine non-success status")
        ms = int((time.perf_counter() - start) * 1000)
        score = sightengine_score(payload)
        is_ai = score >= 50
        used = sightengine_used(payload)
        # Trim the raw payload so vendor internals + media ids don't echo to the
        # browser. Keep scores + the operation count for the quota display.
        raw = {
            "ai_generated": (payload.get("type") or {}).get("ai_generated", 0),
            "operations_used": used,
            "generators": (payload.get("type") or {}).get("ai_generators"),
        }
        return {
            "ran": True,
            "ai_suspected": is_ai,
            "ai_score": score,
            "model": "Sightengine genai (AI-image)",
            "provider": "sightengine",
            "explanation": (
                f"Sightengine's trained model classified this image as "
                f"{'AI-GENERATED' if is_ai else 'not clearly AI'} with {score}% "
                f"confidence (genai model)."
            ),
            "latency_ms": ms,
            "raw": raw,
        }
    except Exception as exc:
        ms = int((time.perf_counter() - start) * 1000)
        return {
            "ran": False, "ai_suspected": False, "ai_score": 0,
            "model": "Sightengine", "provider": "sightengine",
            "explanation": (
                f"Sightengine could not be reached for this check "
                f"(error {exc.__class__.__name__}). The free detector did not run."),
            "latency_ms": ms, "raw": None,
        }

# ----------------------------------------------------------------------------
# section: app/detectors/self_hosted.py (inlined)
# ----------------------------------------------------------------------------
"""
Self-hosted ONNX AI-detection backend (real ViT model, no external service).

Runs a Vision-Transformer classifier locally via ONNX Runtime. The image never
leaves our server. This is the "keep it ours / no API key / no third-party"
option: zero per-image cost and fully private, but it requires a model file on
disk (downloaded on first use) and CPU inference is heavier than a hosted API.

Model: `onnx-community/ai-image-detection-ONNX` â€” ViT-Base fine-tuned on the
CIFAKE dataset (Real vs Fake/AI). Visual Transformer, 224x224 RGB input, two
class logits.

Activation:
    AI_DETECTOR_PROVIDER = self-hosted
    AI_DETECTOR_MODEL_URL  = (optional) direct URL to an .onnx; default HF-hosted
    AI_DETECTOR_MODEL_DIR  = where to cache the model (default: <repo>/data/models)

Limitation note:
    ViT-Base is ~340MB fp32 â€” too big for Vercel's 128MB serverless bundle.
    For Vercel, prefer the Sightengine backend, or host this as a separate small
    CPU worker. Locally (or on a 2-core+ CPU box) it runs fine.
"""

import urllib.request

import numpy as np

# Codebase-aware chat context: indexes the project's own source files (only used
# by the /api/chat assistant) so answers can cite real code paths and lines.
import codebase as codebase_index

# Default small-ish, HF-hosted, Apache-2.0 classifier for Real vs AI.
MODEL_REPO = "onnx-community/ai-image-detection-ONNX"
MODEL_FILE = "model.onnx"
DEFAULT_URL = f"https://huggingface.co/{MODEL_REPO}/resolve/main/onnx/model.onnx"
_IMG_SIZE = 224

_engine = None  # cached onnxruntime.InferenceSession


def _model_dir() -> str:
    return os.getenv("AI_DETECTOR_MODEL_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "models")


def _model_path() -> str:
    url = os.getenv("AI_DETECTOR_MODEL_URL")
    if url:
        return os.path.join(_model_dir(), url.rstrip("/").split("/")[-1])
    local = os.path.join(_model_dir(), MODEL_FILE)
    # Some checkpoints name it differently; prefer an existing file if present.
    for cand in (local, os.path.join(_model_dir(), "pytorch_model.onnx")):
        if os.path.exists(cand):
            return cand
    return local


def _ensure_model() -> str:
    path = _model_path()
    if os.path.exists(path):
        return path
    os.makedirs(_model_dir(), exist_ok=True)
    url = os.getenv("AI_DETECTOR_MODEL_URL") or DEFAULT_URL
    print(f"[detector] downloading AI model -> {path}  ({url})")
    tmp = path + ".download"
    urllib.request.urlretrieve(url, tmp)  # noqa: S310 (intentional model fetch)
    os.replace(tmp, path)
    return path


def _load_engine():
    global _engine
    if _engine is not None:
        return _engine
    import onnxruntime as ort
    path = _ensure_model()
    opts = ort.SessionOptions()
    opts.log_severity_level = 3
    _engine = ort.InferenceSession(path, opts, providers=["CPUExecutionProvider"])
    return _engine


def _preprocess(img_bytes: bytes):
    from PIL import Image
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    img = img.resize((_IMG_SIZE, _IMG_SIZE))
    a = np.asarray(img, dtype=np.float32) / 255.0
    # Channel-first (N, C, H, W) ready for a CNN/ViT-like ONNX graph.
    x = a.transpose(2, 0, 1)[None, ...]
    return x


def onnx_score(output) -> int:
    """Take softmax over the 2 logits and report P(AI) as a 0..100 int."""
    try:
        out = np.asarray(output)
        logits = out.reshape(-1)
        if logits.size < 2:
            return 0
        e = np.exp(logits - logits.max())
        probs = e / e.sum()
        # Model order can be [Real, Fake] or [Fake, Real]. We label the HIGHER
        # probability class and trust the graph's softmax; for robustness we
        # return the max-class confidence mapped to number, and let detect() map
        # via a label hint. Here we assume class index 1 = AI/Fake (most CIFAKE
        # checkpoints use labels ["Real", "Fake"]).
        ai_prob = float(probs[1])
        return int(round(max(0.0, min(100.0, ai_prob * 100.0))))
    except Exception:
        return 0


def onnx_detect(image_bytes: bytes, filename: str = "") -> dict:
    try:
        _load_engine()
    except Exception as exc:
        return {
            "ran": False, "ai_suspected": False, "ai_score": 0,
            "model": "Self-hosted ViT (AI vs Real)", "provider": "self-hosted",
            "explanation": (
                "The self-hosted model could not be started "
                f"(onnxruntime or the model file is missing: {exc.__class__.__name__}). "
                "Install onnxruntime and allow the model download, or switch providers."),
            "latency_ms": 0, "raw": None,
        }
    start = time.perf_counter()
    try:
        x = _preprocess(image_bytes)
        session = _load_engine()
        input_name = session.get_inputs()[0].name
        output = session.run(None, {input_name: x})[0]
        ms = int((time.perf_counter() - start) * 1000)
        score = onnx_score(output)
        is_ai = score >= 50
        return {
            "ran": True,
            "ai_suspected": is_ai,
            "ai_score": score,
            "model": "Self-hosted ViT-Base (CIFAKE fine-tune)",
            "provider": "self-hosted",
            "explanation": (
                f"The on-device Vision Transformer classified this image as "
                f"{'AI-GENERATED' if is_ai else 'not clearly AI'} with {score}% confidence."),
            "latency_ms": ms,
            "raw": {"logits": [float(x) for x in np.asarray(output).reshape(-1)[:2]]},
        }
    except Exception as exc:
        ms = int((time.perf_counter() - start) * 1000)
        return {
            "ran": False, "ai_suspected": False, "ai_score": 0,
            "model": "Self-hosted ViT (AI vs Real)", "provider": "self-hosted",
            "explanation": f"The self-hosted model failed on this image ({exc.__class__.__name__}).",
            "latency_ms": ms, "raw": None,
        }

# ----------------------------------------------------------------------------
# section: app/detectors/__init__.py (inlined)
# ----------------------------------------------------------------------------
"""
AI-content detection orchestrator.

This package turns an uploaded image into a *verifiable, explainable* AI-detection
verdict. It supports two interchangeable backends so the app can run with ZERO
external dependencies (free heuristic) or with a real trained model (cloud API
or a self-hosted ONNX classifier). Every path returns the SAME normalized result
shape, so the rest of the app never cares which detector is active.

Result contract (always returned):
    {
      "ran":              bool,      # did any detector actually inspect pixels?
      "ai_suspected":     bool,      # machine believes this is AI-generated
      "ai_score":         int,       # 0..100 confidence (NOT percentage of a human notch)
      "model":            str | None,# human name of the model used, e.g. "Sightengine v9"
      "provider":         str | None,# "sightengine" | "self-hosted" | "heuristic" | None
      "explanation":      str,       # plain-language, judge-friendly sentence
      "latency_ms":       int,       # how long the detector took
      "raw":              dict | None,
    }
"""

# Backend selection is read ONCE at import time from the environment so the
# running app doesn't re-read files on every call. Env-var names:
#   AI_DETECTOR_PROVIDER   = "sightengine" | "self-hosted" | ""(auto/heuristic)
#   AI_DETECTOR_KEY        = API key for the cloud provider (if any)
#   AI_DETECTOR_ENDPOINT   = optional override for the cloud endpoint
#   AI_DETECTOR_TIMEOUT_MS = budget for the call (default 2500)
#
# COST WARNING: Sightengine's free tier is 2,000 ops/month capped at 500/day,
# and each AI/deepfake check costs FIVE operations. Do NOT make it the sustained
# default or a live crowd will exhaust it in minutes. Prefer the free heuristic
# (default) or the key-free self-hosted ONNX model for the demo ramp.


def _select_backend():
    provider = (os.getenv("AI_DETECTOR_PROVIDER") or "").strip().lower()
    if provider == "sightengine":
        return "sightengine" if os.getenv("AI_DETECTOR_KEY") else "heuristic"
    if provider == "self-hosted":
        return "self-hosted"
    return "heuristic"


BACKEND = _select_backend()

# Resolve the concrete detector function lazily so importing this module never
# pulls heavyweight deps (onnxruntime / requests) unless they are needed.
_detector_ai = None


def _load():
    global _detector_ai
    if _detector_ai is not None:
        return
    if BACKEND == "sightengine":
        _detector_ai = sightengine_detect
    elif BACKEND == "self-hosted":
        _detector_ai = onnx_detect
    else:
        _detector_ai = heuristic_detect


def _empty(explanation, ran=False):
    return {
        "ran": ran,
        "ai_suspected": False,
        "ai_score": 0,
        "model": None,
        "provider": None,
        "explanation": explanation,
        "latency_ms": 0,
        "raw": None,
    }


def detect_image(image_bytes: bytes, filename: str = "") -> dict:
    """Public entry point. Runs the active backend and returns the normalized
    verdict. Never raises: any internal failure degrades to a clean, honest
    'unable to inspect' result so a verify request can never 500.

    Scanned-document pre-check: if the image reads as a text/page document
    (e.g. a scanned notice) we skip the AI-art detectors entirely â€” they are
    trained for photos and would misfire and waste the cloud budget. Instead we
    return a document verdict that points trust to the signature/provenance."""
    if not image_bytes:
        return _empty("No image data was provided, so it could not be analysed for AI generation.")
    start = time.perf_counter()
    try:
        is_doc = looks_like_scanned_document(image_bytes)
        ms_scan = int(round((time.perf_counter() - start) * 1000))
        if is_doc:
            out = document_verdict(filename)
            out["latency_ms"] = ms_scan
            return out
        _load()
        result = _detector_ai(image_bytes, filename)
        # Always report the real measured elapsed time (even for the fast
        # heuristic) so the analytics latency graph is honest across backends.
        result["latency_ms"] = int(round((time.perf_counter() - start) * 1000))
        return result
    except Exception as exc:  # defensive: provider/models can fail; degrade cleanly
        ms = int((time.perf_counter() - start) * 1000)
        out = _empty(
            "The AI-detection model could not be run on this image right now. "
            f"(detector unavailable: {exc.__class__.__name__})"
        )
        out["latency_ms"] = ms
        return out


def explain(result: dict) -> str:
    """Return a one-line, judge-friendly summary of a normalized result."""
    if not result or not result.get("ran"):
        return "No AI-detection model ran, so we cannot say whether this was machine-made."
    score = result.get("ai_score", 0)
    model = result.get("model") or "the local detector"
    if result.get("ai_suspected"):
        return (f"{model} classified this image as AI-generated with "
                f"{score}% confidence.")
    return (f"{model} found no strong AI-generation signature "
            f"(confidence of AI was {score}%).")


# ==============================================================================
# [ COLUMN 1: ENVIRONMENT & DB CONFIG ]
# ==============================================================================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "").strip().replace("postgres://", "postgresql://", 1)
if not DATABASE_URL:
    sys.exit("\n[FATAL] DATABASE_URL is not set.\n"
             "  -> Copy .env.example to .env and set DATABASE_URL before starting.\n"
             "  Example: DATABASE_URL=postgresql://USER:PASSWORD@HOST/PORT/DB?sslmode=require\n")

if "sqlite" not in DATABASE_URL:
    import psycopg2

    # Neon DNS on this network is flaky (`could not translate host name ...`).
    # connect_timeout bounds the TCP/SSL phases but NOT DNS resolution, so a
    # transient resolver blip used to hang requests for the OS timeout. Retrying
    # the raw connect a few times turns that into a fast recover instead.
    def _pg_creator(**kw):
        last = None
        for attempt in range(3):
            try:
                return psycopg2.connect(DATABASE_URL, connect_timeout=10, **kw)
            except Exception as e:
                last = e
                if attempt < 2:
                    time.sleep(0.4 * (attempt + 1))
        raise last or RuntimeError("PostgreSQL connect failed")

    # Performance: serverless instances recycle between requests, so every DB op
    # used to do a cold TLS handshake to Neon (~2s+ on a stale socket). Explicitly
    # pool a small set of warm connections and recycle BEFORE Neon's 300s idle
    # timeout so a checkout reuses a live socket instead of pre-ping discovering a
    # dead one and reconnecting inline. appname helps profile this in Neon.
    engine = create_engine(
        DATABASE_URL,
        creator=_pg_creator,
        pool_pre_ping=True,
        pool_size=3,
        max_overflow=5,
        pool_recycle=290,          # just under Neon's 300s idle conn eviction
        pool_timeout=15,
        connect_args={"application_name": "nocap"},
    )
else:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

RAW_KEY = os.getenv("MASTER_VAULT_KEY", "").encode("utf-8")
if not RAW_KEY:
    sys.exit("\n[FATAL] MASTER_VAULT_KEY is not set.\n"
             "  -> Copy .env.example to .env and set a 32+ byte MASTER_VAULT_KEY.\n"
             "  NOTE: Changing this key AFTER identities exist breaks access to their KMS keys.\n")
MASTER_VAULT_KEY = RAW_KEY.ljust(32, b"0")[:32]

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
if not GOOGLE_CLIENT_ID:
    sys.exit("\n[FATAL] GOOGLE_CLIENT_ID is not set.\n"
             "  -> Set the OAuth 2.0 Client ID of your Google Workspace project in .env.\n")

# --- Web3 & IPFS Config (optional: simulated when empty) ---
WEB3_RPC_URL = os.getenv("WEB3_RPC_URL", "")  
WALLET_PRIV_KEY = os.getenv("WALLET_PRIVATE_KEY", "")
PINATA_JWT = os.getenv("PINATA_JWT", "")
BLOCKCHAIN_EXPLORER_URL = os.getenv("BLOCKCHAIN_EXPLORER_URL", "https://amoy.polygonscan.com/tx/")

# --- Sign-in authorization (NOT hardcoded email lists) -----------------------
# Who may log in is decided by Google Cloud itself:
#   * ALLOWED_DOMAINS  - comma-separated Google-hosted domains (id_token `hd`),
#                        e.g. "soa.ac.in,iter.ac.in". Anyone whose Google Cloud
#                        account belongs to one of these domains is allowed and
#                        is added automatically â€” no code edit needed.
#   * ALLOWED_EMAILS   - optional comma-separated exact emails (e.g. personal
#                        gmail accounts, which carry no `hd` claim).
# Super admins ALWAYS bypass the gate so the owner can never be locked out.
ALLOWED_DOMAINS = {d.strip().lower() for d in os.getenv("ALLOWED_DOMAINS", "").split(",") if d.strip().lower()}
ALLOWED_EMAILS = {e.strip().lower() for e in os.getenv("ALLOWED_EMAILS", "").split(",") if e.strip().lower()}

SUPER_ADMINS = [
    "asutoshn06@gmail.com",
    "ayushlenka2020@gmail.com",
    "dikhyantsatpathy@gmail.com"
]

def is_super_admin(email: str) -> bool:
    return email.strip().lower() in [e.strip().lower() for e in SUPER_ADMINS]

# ==============================================================================
# [ COLUMN 2: DATABASE MODELS ]
# ==============================================================================

class SignerIdentity(Base):
    __tablename__ = "signer_identities"
    email = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    institution = Column(String, nullable=True)
    designation = Column(String, nullable=True)
    pub_key = Column(String, nullable=False)
    enc_priv_key = Column(String, nullable=False)
    is_revoked = Column(Boolean, default=False)
    registered_at = Column(String, nullable=False)
    revoked_at = Column(String, nullable=True)
    revoke_pin = Column(String, nullable=True)

class LedgerBlock(Base):
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    signer_email = Column(String, nullable=False)
    signer_name = Column(String, nullable=False)
    signer_institution = Column(String, nullable=True)
    signer_designation = Column(String, nullable=True)
    filename = Column(String, nullable=False)
    file_hash = Column(String, unique=True, index=True, nullable=False)
    sig_hex = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    ipfs_cid = Column(String, nullable=True)
    tx_hash = Column(String, nullable=True)       # NEW: Web3 L2 Transaction Hash
    merkle_root = Column(String, nullable=True)   # NEW: Merkle Root
    is_revoked = Column(Boolean, default=False)
    notice_content = Column(String, nullable=True)      # NEW: raw emergency text (public board)
    notice_deleted = Column(Boolean, default=False)     # NEW: retracted by the issuing authority
    notice_media_type = Column(String, nullable=True)   # NEW: MIME type of attached image/video
    notice_media_name = Column(String, nullable=True)   # NEW: original filename of attached media
    flag_count = Column(Integer, default=0)             # NEW: community forgery reports
    notice_media_data = Column(LargeBinary, nullable=True)  # NEW: raw bytes of attached media

class VerificationLog(Base):
    __tablename__ = "verification_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_hash = Column(String, nullable=False)
    status = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    detection_ms = Column(Integer, default=0)             # AI-detector latency (ms)
    detection_provider = Column(String, nullable=True)   # heuristic | sightengine | self-hosted | None

class PendingUpload(Base):
    """Durable, DB-backed chunk buffer for signing a SINGLE file that exceeds
    Vercel's ~4.4MB request-body cap. The client slices the file into small
    pieces and posts each as its own /api/sign_chunk request (each well under
    the edge cap); we persist the raw chunk bytes here keyed by (session_id,
    chunk_index). The /api/sign_complete endpoint reassembles them, runs the
    normal sign pipeline, records ONE ledger block, and returns the signed file.
    Using Postgres (Neon) instead of in-memory is deliberate: serverless
    instances can be recycled between chunk requests, so we must not rely on
    instance-local state."""
    __tablename__ = "pending_uploads"
    session_id = Column(String, primary_key=True, index=True)
    chunk_index = Column(Integer, primary_key=True)
    total_chunks = Column(Integer, nullable=False)
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    data = Column(LargeBinary, nullable=False)
    created_at = Column(String, nullable=False)

class SightengineUsage(Base):
    """Persistent, cumulative Sightengine operation counters so the UI can show
    an honest "uses remaining" without exposing the API key or vendor internals.
    A single singleton row (key='global') tracks today's + month's consumption."""
    __tablename__ = "sightengine_usage"
    row_key = Column(String, primary_key=True)
    ops_today = Column(Integer, default=0)
    ops_month = Column(Integer, default=0)
    day_date = Column(String, nullable=True)   # YYYY-MM-DD the ops_today applies to
    month = Column(String, nullable=True)      # YYYY-MM the ops_month applies to
    updated_at = Column(String, nullable=True)

class ScreeningReport(Base):
    """One MHA identity-document screening pass (SIH26188). An immutable audit
    record: stores NO raw bytes or extracted text â€” only the SHA-256 hash of
    the file, MASKED identifier fields, and explainable signals (the same
    zero-storage discipline as the whole ledger)."""
    __tablename__ = "screening_reports"
    id = Column(String, primary_key=True)
    file_hash = Column(String, index=True, nullable=False)
    filename = Column(String, nullable=False)
    doc_type = Column(String, nullable=True)
    checkpoint = Column(String, nullable=True)
    verdict = Column(String, nullable=False)         # CLEAR | REVIEW | FLAGGED
    risk_score = Column(Integer, nullable=False)
    confidence = Column(Float, nullable=False)
    extracted_fields = Column(Text, nullable=False)  # masked JSON
    signals = Column(Text, nullable=False)           # reasons JSON
    ai_detection = Column(Text, nullable=True)       # detector snapshot JSON
    modules = Column(Text, nullable=True)            # Module 1-4 verdicts JSON
    ledger_status = Column(String, nullable=True)    # AUTHENTIC | REVOKED | UNKNOWN
    adjudication = Column(String, nullable=True)     # CLEARED | CONFIRMED_FRAUD | INCONCLUSIVE
    adjudicator = Column(String, nullable=True)
    adjudication_note = Column(String, nullable=True)
    adjudicated_at = Column(String, nullable=True)
    screener = Column(String, nullable=True)         # signed-in officer who ran it
    created_at = Column(String, nullable=False)

class WatchlistEntry(Base):
    """Privacy-preserving watchlist for the screening desk: stores ONLY the
    SHA-256 hash of the NORMALIZED identifier plus a masked display label and
    a search reason. Raw identifier values never touch the database."""
    __tablename__ = "watchlist_entries"
    id = Column(Integer, primary_key=True, autoincrement=True)
    identifier_hash = Column(String, index=True, unique=True, nullable=False)
    category = Column(String, nullable=True)         # pan | passport | visa | driving_licence | voter_id | phone | ...
    mask = Column(String, nullable=True)             # e.g. ****1234
    reason = Column(String, nullable=True)
    added_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)

try:
    Base.metadata.create_all(bind=engine)
except Exception:
    # Best-effort: a transient Neon DNS blip must never abort startup. Schema
    # drift is still handled by the idempotent migration pass below.
    print("[startup] warning: create_all deferred (DB unreachable now).")

_IS_SQLITE = "sqlite" in DATABASE_URL

_MIGRATIONS = [
    "ALTER TABLE signer_identities ADD COLUMN IF NOT EXISTS institution VARCHAR;",
    "ALTER TABLE signer_identities ADD COLUMN IF NOT EXISTS designation VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_email VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_name VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_institution VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_designation VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS tx_hash VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS merkle_root VARCHAR;",
    "ALTER TABLE signer_identities ADD COLUMN IF NOT EXISTS revoke_pin VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_content TEXT;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_deleted BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_media_type VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_media_name VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_media_data " + ("BYTEA" if not _IS_SQLITE else "BLOB") + ";",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS flag_count INTEGER DEFAULT 0;",
    # AI-detection latency + provider per verify (powers the analytics latency graph).
    "ALTER TABLE verification_logs ADD COLUMN IF NOT EXISTS detection_ms INTEGER DEFAULT 0;",
    "ALTER TABLE verification_logs ADD COLUMN IF NOT EXISTS detection_provider VARCHAR;",
    # Signing latency fix: file_hash is now UNIQUE at the DB level, so a re-sign
    # of identical bytes is a no-op single statement instead of a select+insert.
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_blocks_file_hash ON blocks(file_hash);",
    # Chunked upload buffer for signing single files over Vercel's ~4.4MB cap.
    "CREATE TABLE IF NOT EXISTS pending_uploads (session_id VARCHAR NOT NULL, "
    "chunk_index INTEGER NOT NULL, total_chunks INTEGER NOT NULL, "
    "filename VARCHAR NOT NULL, content_type VARCHAR, "
    "data " + ("BYTEA" if not _IS_SQLITE else "BLOB") + " NOT NULL, "
    "created_at VARCHAR NOT NULL, PRIMARY KEY (session_id, chunk_index));",
    # Sightengine op-count tracking for the "uses remaining" quota display.
    "CREATE TABLE IF NOT EXISTS sightengine_usage (row_key VARCHAR NOT NULL, "
    "ops_today INTEGER DEFAULT 0, ops_month INTEGER DEFAULT 0, "
    "day_date VARCHAR, month VARCHAR, updated_at VARCHAR, "
    "PRIMARY KEY (row_key));",
    # Hot-path indexes: GROUP BY / ORDER BY / filter columns that previously
    # full-scanned as the ledger and verification log grew. Plain (non-unique)
    # so pre-existing rows can never break the migration pass.
    "CREATE INDEX IF NOT EXISTS ix_verification_logs_status ON verification_logs(status);",
    "CREATE INDEX IF NOT EXISTS ix_verification_logs_provider ON verification_logs(detection_provider);",
    "CREATE INDEX IF NOT EXISTS ix_verification_logs_file_hash ON verification_logs(file_hash);",
    "CREATE INDEX IF NOT EXISTS ix_verification_logs_ts ON verification_logs(timestamp);",
    "CREATE INDEX IF NOT EXISTS ix_blocks_signer_email ON blocks(signer_email);",
    "CREATE INDEX IF NOT EXISTS ix_blocks_tx_hash ON blocks(tx_hash);",
    "CREATE INDEX IF NOT EXISTS ix_blocks_ts ON blocks(timestamp);",
    "CREATE INDEX IF NOT EXISTS ix_blocks_designation ON blocks(signer_designation);",
    "CREATE INDEX IF NOT EXISTS ix_pending_uploads_created ON pending_uploads(created_at);",
    "CREATE INDEX IF NOT EXISTS ix_screening_reports_created ON screening_reports(created_at);",
    "CREATE INDEX IF NOT EXISTS ix_screening_reports_screener ON screening_reports(screener);",
    "CREATE INDEX IF NOT EXISTS ix_screening_reports_verdict ON screening_reports(verdict);",
    "CREATE INDEX IF NOT EXISTS ix_screening_reports_chk_created ON screening_reports(checkpoint, created_at);",
    "CREATE INDEX IF NOT EXISTS ix_watchlist_created ON watchlist_entries(created_at);",
    # Watchlist dedup guard: same identifier must not appear twice even under
    # concurrent adds (the insert path tolerates IntegrityError and returns the
    # existing row). Skipped automatically if legacy duplicate rows exist.
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_watchlist_identifier ON watchlist_entries(identifier_hash);",
    # Screening desk Module 1-4 verdicts (SIH26188): JSON row per pass so the
    # digital trail shows which subsystem — OCR/validation/tampering/face —
    # produced each conclusion, not just the final risk score.
    "ALTER TABLE screening_reports ADD COLUMN IF NOT EXISTS modules TEXT;",
]

print("[startup] running schema migration...")
# Reuse ONE connection for the whole idempotent pass. On serverless cold starts
# and when Neon is flaky, each statement used to do its own connect + pre-ping
# (3-attempt retries each), so 31 tiny DDL statements cost ~31 slow handshakes.
# Each statement COMMITS on its own (a failed `IF NOT EXISTS` / unique-index
# guard must not abort a transaction that silently swallows every later step).
try:
    with engine.connect() as conn:
        for stmt in _MIGRATIONS:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception as e:
                conn.rollback()
                # Never swallow silently: a failed statement is either benign (column/
                # index already exists — note SQLite rejects ADD COLUMN IF NOT EXISTS,
                # where create_all above is the real schema source) or a genuine typo
                # that must be visible in the deploy logs.
                print(f"[startup] migration skipped ({type(e).__name__}): {stmt[:90]}")
except Exception as e:
    # A single connect failure (transient DNS / cold Neon) skips the entire pass;
    # best-effort, same as create_all above — never abort startup.
    print(f"[startup] migration pass skipped ({type(e).__name__}): {e}")
print("[startup] schema migration pass complete.")

if not _IS_SQLITE:
    # The old helper relied on a plain (non-unique) lookup index; the unique
    # index above fully supersedes it. Dropped on Postgres only â€” sqlite's
    # own ix_blocks_file_hash is the brand-new constraint backing its COLUMN.
    try:
        with engine.begin() as conn:
            conn.execute(text("DROP INDEX IF EXISTS ix_blocks_file_hash;"))
    except Exception:
        pass

# --- Neon (serverless Postgres) pauses after ~5 min of idle; the FIRST request
#     then pays a 5-20s cold start. For demos this reads as "signing is slow",
#     so a lightweight daemon keeps the compute awake. Set KEEPALIVE_INTERVAL=0
#     to disable, or raise it (seconds) for battery-friendlier sleep. ---
def _start_keepalive() -> None:
    if os.getenv("VERCEL") == "1":
        return  # serverless: instances are short-lived, a daemon thread would be pointless
    interval = float(os.getenv("KEEPALIVE_INTERVAL", "45"))
    if _IS_SQLITE or interval <= 0:
        return

    def _ping_loop():
        while True:
            time.sleep(interval)
            try:
                with engine.connect() as c:
                    c.execute(text("SELECT 1"))
            except Exception:
                pass  # network hiccup or explicit shutdown - keep trying

    threading.Thread(target=_ping_loop, daemon=True, name="neon-keepalive").start()

_start_keepalive()

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        # A failed commit leaves the session in a broken state; roll back so a
        # caller that reuses the session (chunk cleanup, follow-up queries)
        # does not trip PendingRollbackError — then re-raise.
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()

def now_utc(): 
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

# ==============================================================================
# [ COLUMN 3: CRYPTOGRAPHY & KMS VAULT ]
# ==============================================================================

def derive_owner_key(owner_email: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=owner_email.strip().lower().encode('utf-8'), info=b"nischay-owner-vault-key-v1")
    return hkdf.derive(MASTER_VAULT_KEY)

def encrypt_vault_key(pem_bytes: bytes, owner_email: str) -> str:
    aesgcm = AESGCM(derive_owner_key(owner_email))
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, pem_bytes, None)
    return base64.b64encode(nonce + ct).decode('utf-8')

def decrypt_vault_key(enc_str: str, owner_email: str) -> bytes:
    data = base64.b64decode(enc_str)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(derive_owner_key(owner_email))
    return aesgcm.decrypt(nonce, ct, None)

def make_session_token(email: str) -> str:
    """Mint a self-contained session token: email + expiry + HMAC.

    No server-side session store is needed — the signature proves issuance and
    the embedded expiry bounds the lifetime (1 day, matching the cookie
    max_age). A leaked token stops working after expiry even if the cookie's
    client-side max_age is tampered with."""
    email = email.strip().lower()
    exp = int(datetime.now(timezone.utc).timestamp()) + 86400
    sig = hmac.new(MASTER_VAULT_KEY, f"{email}::{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{email}::{exp}::{sig}"

def get_current_admin(request: Request):
    token = request.cookies.get("nischay_session")
    if not token or token.count("::") != 2:
        raise HTTPException(status_code=401, detail="ACCESS DENIED: Missing or invalid secure session cookie.")
    email, exp_raw, sig = token.split("::")
    expected = hmac.new(MASTER_VAULT_KEY, f"{email}::{exp_raw}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="ACCESS DENIED: Session signature invalid or tampered.")
    try:
        exp = int(exp_raw)
    except ValueError:
        raise HTTPException(status_code=401, detail="ACCESS DENIED: Session signature invalid or tampered.")
    if exp < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=401, detail="ACCESS DENIED: Session expired — please sign in again.")
    return email

def get_or_create_signer_identity(db, email: str, google_name: str) -> SignerIdentity:
    identity = db.query(SignerIdentity).filter_by(email=email).first()
    if identity: return identity

    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    priv_pem = priv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    enc_priv = encrypt_vault_key(priv_pem.encode('utf-8'), owner_email=email)

    identity = SignerIdentity(
        email=email, name=(google_name or email).strip()[:200], designation=None,
        pub_key=pub_pem, enc_priv_key=enc_priv, registered_at=now_utc()
    )
    db.add(identity)
    try:
        db.commit()
    except IntegrityError:
        # Concurrent first-login for the same email: the winner's row is now
        # durable, so fall back to it instead of 500ing the loser.
        db.rollback()
        identity = db.query(SignerIdentity).filter_by(email=email).first()
        if identity is None:
            raise
    db.refresh(identity)
    return identity

# ==============================================================================
# [ COLUMN 4: DEEPFAKE FORENSICS & WEB3 ANCHORING ]
# ==============================================================================

def upload_receipt_to_ipfs(receipt_dict: dict) -> str:
    """Zero-Knowledge Privacy: Anchors only JSON metadata, preventing plaintext file leaks."""
    if not PINATA_JWT:
        simulated_hash = hashlib.sha256(json.dumps(receipt_dict, sort_keys=True).encode()).hexdigest()
        return f"QmReceipt{simulated_hash[:38]}"
    try:
        receipt_bytes = json.dumps(receipt_dict, indent=2).encode("utf-8")
        import requests
        res = requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS", headers={"Authorization": f"Bearer {PINATA_JWT}"}, files={"file": (f"receipt_{receipt_dict.get('file_hash', 'blob')[:12]}.json", receipt_bytes)}, timeout=8)
        return res.json().get("IpfsHash", "IPFS_PIN_FAILED")
    except Exception: return "IPFS_NETWORK_ERROR"

def inject_media_trap(file_bytes: bytes, filename: str, signer_label: str, sig_hex: str, timestamp: str) -> bytes:
    """Injects Nocap signatures natively into PDF, MP3, and MP4 containers."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    try:
        from pypdf import PdfReader
        from mutagen.id3 import TXXX
        from mutagen.mp4 import MP4
        if ext == "pdf":
            from pypdf import PdfWriter
            reader, writer = PdfReader(io.BytesIO(file_bytes)), PdfWriter()
            for page in reader.pages: writer.add_page(page)
            writer.add_metadata({"/Nocap_Issuer": signer_label, "/Nocap_Signature": sig_hex, "/Nocap_Timestamp": timestamp})
            out = io.BytesIO()
            writer.write(out)
            return out.getvalue()
        elif ext in ["mp3", "wav"]:
            audio_io = io.BytesIO(file_bytes)
            from mutagen.id3 import ID3, ID3NoHeaderError
            try: tags = ID3(audio_io)
            except ID3NoHeaderError: tags = ID3()
            tags.add(TXXX(encoding=3, desc="NOCAP_ISSUER", text=signer_label))
            tags.add(TXXX(encoding=3, desc="NOCAP_SIG", text=sig_hex))
            tags.save(audio_io)
            return audio_io.getvalue()
        elif ext in ["mp4", "m4a", "mov"]:
            mp4_io = io.BytesIO(file_bytes)
            tags = MP4(mp4_io)
            tags["\xa9cmt"] = f"NOCAP_VERIFIED|ISSUER:{signer_label}|SIG:{sig_hex}|TIME:{timestamp}"
            tags.save(mp4_io)
            return mp4_io.getvalue()
        elif ext in ["jpg", "jpeg", "png", "gif"] and _import_pil() is not None:
            import PIL.Image as _PILImage  # lazy, only on the image-sign path
            marker = f"NOCAP_VERIFIED|ISSUER:{signer_label}|SIG:{sig_hex}|TIME:{timestamp}"
            out = io.BytesIO()
            img = _PILImage.open(io.BytesIO(file_bytes))
            img.load()
            if ext in ("jpg", "jpeg") and file_bytes[:2] == b"\xff\xd8":
                # Insert a JPEG COM (comment) segment right after the SOI marker.
                # Survives most editors that rewrite EXIF, and IS detected by our
                # raw marker scan without needing Pillow's EXIF TIFF writer.
                seg = bytes([0xFF, 0xFE]) + (len(marker) + 2).to_bytes(2, "big") + marker.encode("utf-8")
                return file_bytes[:2] + seg + file_bytes[2:]
            if ext in ("png", "gif"):
                # PNG/GIF: write a tEXt text chunk. Preserve the source's own
                # text/EXIF labels (e.g. "Software: stable-diffusion-webui") so
                # signing an AI/edited image does NOT launder away its origin.
                try:
                    from PIL.PngImagePlugin import PngInfo
                    png = PngInfo()
                    png.add_text("Nocap_Verified", marker)
                    for k, v in img.info.items():
                        if isinstance(v, str) and k.lower() not in ("ncap_verified", "nocap_verified") and k:
                            try:
                                png.add_text(k, v[:400])
                            except Exception:
                                pass
                    img.save(out, format=("GIF" if ext == "gif" else "PNG"), pnginfo=png,
                             exif=img.info.get("exif"))
                    if out.tell() > 0:
                        return out.getvalue()
                except Exception:
                    pass
            return file_bytes
    except Exception as e:
        print(f"Trap warning {ext}: {e}")
    return file_bytes

def extract_media_trap(file_bytes: bytes, filename: str) -> bool:
    """Checks for trapped metadata in manipulated media."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    try:
        from pypdf import PdfReader
        from mutagen.id3 import ID3, TXXX
        from mutagen.mp4 import MP4
        if ext == "pdf": return "/Nocap_Issuer" in (PdfReader(io.BytesIO(file_bytes)).metadata or {})
        if ext in ["mp3", "wav"]: return any(isinstance(f, TXXX) and f.desc in ["NOCAP_ISSUER", "NOCAP_SIG"] for f in ID3(io.BytesIO(file_bytes)).values())
        if ext in ["mp4", "m4a", "mov"]: return "NOCAP_VERIFIED" in str(MP4(io.BytesIO(file_bytes)).get("\xa9cmt", [""])[0])
        if ext in ("jpg", "jpeg", "png", "gif") and (
                "NOCAP_VERIFIED" in _image_metadata_text(file_bytes, ext) or
                _NOCAP_MARKER in file_bytes):
            return True
    except Exception: pass
    return False


_NOCAP_MARKER = b"NOCAP_VERIFIED"

# ==============================================================================
# [ FORENSIC REASON-OF-FORGERY ]
# Reads the metadata/containers of a file to explain, in PLAIN language, why it
# looks edited/forged/AI-made. This is metadata + container forensics: it names
# the editing app or AI generator a forgery leaks in its own metadata, and it
# cross-checks our cryptographic trap. It is an INDICATOR, never conclusive
# proof of AI generation on a stripped/clean image (that needs pixel/ML work,
# out of scope for the serverless Vercel deployment).
# ==============================================================================

# Editing-software signatures that leaks into produced files.
_EDITING_SIGS = {
    "Adobe Photoshop": "a graphic-design app (Adobe Photoshop)",
    "photoshop": "the photo-editor Adobe Photoshop",
    "Adobe ImageReady": "an image tool (Adobe ImageReady)",
    "Adobe Illustrator": "a vector-design app (Adobe Illustrator)",
    "GIMP": "a free photo-editor (GIMP)",
    "Canva": "the Canva design app",
    "Affinity": "Affinity (a design app)",
    "Pixelmator": "Pixelmator (a photo-editor)",
    "Inkscape": "Inkscape (a vector editor)",
    "Photopea": "Photopea (a browser photo-editor)",
    "Paint.NET": "Paint.NET (a photo-editor)",
    "Sketch": "the Sketch design app",
    "Figma": "the Figma design tool",
    "CorelDRAW": "the vector editor CorelDRAW",
    "Lightroom": "the photo-editor Adobe Lightroom",
    "PhotoDirector": "the photo-editor PhotoDirector",
    "PhotoScape": "the photo-editor PhotoScape",
    "PicMonkey": "the photo-editor PicMonkey",
    "BeFunky": "the photo-editor BeFunky",
    "PaintShop Pro": "the photo-editor PaintShop Pro",
    "Apple Preview": "the viewer Apple Preview",
    "Snapseed": "the photo-editor Snapseed",
    "PicsArt": "the photo-editor PicsArt",
    "VSCO": "the photo-editor VSCO",
    "Luminar": "the photo-editor Luminar",
    "Darkroom": "the photo-editor Darkroom",
    "RawTherapee": "the photo-editor RawTherapee",
    "darktable": "the photo-editor darktable",
    "Edits by Xara": "the design app Xara",
    "Autodesk Pixlr": "the photo-editor Pixlr",
    "ON1 Photo": "the photo-editor ON1",
    "Capture One": "the RAW editor Capture One",
    "Polish": "the photo-editor Polish",
    "Fotor": "the photo-editor Fotor",
}

# AI-generator / AI-upscaler signatures that self-tag generated media. This now
# includes the upscalers and enhancers people actually use (Canva's magic resize,
# Topaz, ESRGAN, Magnific, upscayl, img2go, waifu2x, etc.) so an AI-upscaled
# photo that keeps its metadata gets flagged instead of passing clean.
_AI_SIGS = {
    "Midjourney": "the AI image generator Midjourney",
    "DALL-E": "OpenAI's AI image generator DALL-E",
    "OpenAI Images": "OpenAI's AI image generator",
    "Stable Diffusion": "the AI generator Stable Diffusion",
    "SDXL": "the AI model SDXL",
    "ComfyUI": "the AI workflow tool ComfyUI",
    "Adobe Firefly": "Adobe's AI generator Firefly",
    "Leonardo": "the AI generator Leonardo",
    "Ideogram": "the AI generator Ideogram",
    "Nano Banana": "the AI image model Nano Banana",
    "FLUX": "the AI image model FLUX",
    "Imagen": "Google's AI image generator Imagen",
    "Firefly": "Adobe's AI model Firefly",
    "Topaz": "the AI upscaler Topaz",
    "Topaz Photo AI": "the AI upscaler Topaz Photo AI",
    "Topaz Gigapixel": "the AI upscaler Topaz Gigapixel",
    "ESRGAN": "the AI upscaler ESRGAN",
    "Real-ESRGAN": "the AI upscaler Real-ESRGAN",
    "Magnific": "the AI upscaler Magnific",
    "Magnific.ai": "the AI upscaler Magnific",
    "Upscayl": "the AI upscaler Upscayl",
    "waifu2x": "the AI upscaler waifu2x",
    "img2go": "the AI tool img2go",
    "AI Enhance": "an AI photo enhancer",
    "Enhance AI": "an AI photo enhancer",
    "Neuro Night": "an AI upscaler (Neuro Night)",
    "RemoveBG": "the AI background-remover remove.bg",
    "Magic Resize": "Canva's AI upscaler (Magic Resize)",
    "Dream AI": "an AI image tool (Dream AI)",
    "Stable Diffusion XL": "the AI model SDXL",
    "Gemini": "Google's Gemini AI (image/text generator)",
    "Gemini Advanced": "Google's Gemini AI model",
    "Ideogram 3.0": "the AI generator Ideogram",
    "Recraft": "the AI generator Recraft",
    "Krea": "the AI generator Krea",
    "Runway": "the AI video/image generator Runway",
    "Runway Gen-3": "the AI generator Runway Gen-3",
    "Sora": "OpenAI's AI video generator Sora",
    "Veo": "Google's AI video model Veo",
    "Pika": "the AI video generator Pika",
    "Luma Dream Machine": "the AI video generator Luma Dream Machine",
    "Luma": "the AI video generator Luma",
    "Genie": "Google's AI image model Genie",
    "Stable Video": "the AI video model Stable Video",
    "FLUX (Tensor)": "the AI image model FLUX",
    "Tensor DiffusionArt": "the AI image model FLUX",
    "AnythingXL": "the AI image model AnythingXL",
    "AlbedoBase XL": "the AI image model AlbedoBase XL",
    "DreamShaper": "the AI image model DreamShaper",
    "Juggernaut XL": "the AI image model Juggernaut XL",
    "Kandinsky": "the AI image generator Kandinsky",
    "Wombo": "the AI image app Wombo Dream",
    "Hotpot": "the AI tool Hotpot.ai",
    "Fotor": "the AI photo editor Fotor (AI effects)",
    "Pixlr AI": "the AI editor Pixlr (AI features)",
    "Zyro": "the AI design tool Zyro (AI features)",
    "NightCafe": "the AI generator NightCafe",
    "DreamStudio": "the AI generator DreamStudio",
    "Playground Mod": "the AI generator Playground (Mod)",
    "DiffusionBee": "the AI generator DiffusionBee",
    "InvokeAI": "the AI generator InvokeAI",
    "Fooocus": "the AI generator Fooocus",
    "Artbreeder": "the AI face/id tool Artbreeder",
    "BigGAN": "the generative model BigGAN",
    "StyleGAN": "the generative model StyleGAN",
    "VQGAN": "the generative model VQGAN",
    "DALL-E 3": "OpenAI's AI image generator DALL-E 3",
    "Black Forest": "the AI studio Black Forest Labs (FLUX)",
}


# Precomputed lowercase/sanitized lookup keys (no per-call regex/normalization).
_AI_LOOKUP = {tool.lower().replace("-", " ").replace(".", " "): tool for tool in _AI_SIGS}
_EDITING_LOOKUP = {tool.lower().replace("-", " ").replace(".", " "): tool for tool in _EDITING_SIGS}


def _match_tool(text: str) -> tuple:
    """Scan text for EVERY known editing/AI tool and return the strongest kind
    plus a human reason. Also returns a confidence score (0..1): direct, long,
    descriptor-rich AI self-tags are the most reliable; editing mentions are a
    little less certain. An AI-upscaled file often names BOTH an editor and an AI
    tool (e.g. 'Canva' + 'Topaz Photo AI') â€” we want the AI signal to dominate so
    the user sees it was AI-processed, not just 'edited'."""
    t = (text or "").lower().replace("-", " ").replace("_", " ").replace(".", " ")
    found_ai = [k for k in _AI_LOOKUP if k in t]
    found_edit = [k for k in _EDITING_LOOKUP if k in t]
    if found_ai:
        tool = _AI_LOOKUP[max(found_ai, key=len)]
        return ("ai", tool, f"Made by {_AI_SIGS[tool]}.", 0.9)
    if found_edit:
        tool = _EDITING_LOOKUP[max(found_edit, key=len)]
        return ("edited", tool, f"Edited in {_EDITING_SIGS[tool]}.", 0.65)
    return (None, None, None, None)


def _image_metadata_text(file_bytes: bytes, ext: str) -> str:
    """Extract embedded text labels (EXIF/XMP/PNG-text/RIFF) from image bytes using
    ONLY the standard library, so we can name editing/AI tools even on files whose
    producer never printed into PDF/MP3/MP4 metadata. Works for JPEG (APP1 EXIF/XMP),
    PNG (tEXt/iTXt/tEXt/zTXt chunks) and WebP (RIFF/V8 EXIF)."""
    out_parts = []
    try:
        data = file_bytes

        # --- PNG: walk chunks, decode text chunks ---
        if ext == "png" and data[:8] == b"\x89PNG\r\n\x1a\n":
            pos = 8
            while pos + 8 <= len(data):
                (ln,) = __import__("struct").unpack(">I", data[pos:pos + 4])
                ctype = data[pos + 4:pos + 8]
                body = data[pos + 8:pos + 8 + ln]
                if ctype in (b"tEXt", b"iTXt", b"tEXt", b"zTXt") or ctype == b"tEXt" or ctype in (b"iTXt", b"zTXt", b"tEXt"):
                    try:
                        if ctype == b"tEXt" or ctype == b"tEXt":
                            k, _, v = bytes(body).partition(b"\x00")
                            out_parts.append(bytes(body).decode("latin-1", "ignore"))
                        elif ctype == b"iTXt":
                            out_parts.append(bytes(body).decode("latin-1", "ignore"))
                        elif ctype == b"zTXt":
                            import zlib
                            try:
                                k, sep, rest = bytes(body).partition(b"\x00")
                                if rest:
                                    out_parts.append(zlib.decompress(rest[1:]).decode("latin-1", "ignore"))
                            except Exception: pass
                    except Exception: pass
                pos += 12 + ln
        # --- JPEG: walk segments, pull APP1 (EXIF '\x45\x58\x49\x46' and XMP) ---
        elif ext in ("jpg", "jpeg") and data[:2] == b"\xff\xd8":
            pos = 2
            while pos + 4 <= len(data):
                if data[pos] != 0xFF:
                    break
                marker = data[pos + 1]
                (seg_len,) = __import__("struct").unpack(">H", data[pos + 2:pos + 4])
                if seg_len < 2 or pos + 2 + seg_len > len(data):
                    break
                seg = data[pos + 4:pos + 2 + seg_len]
                # APP1 (0xE1): EXIF (Exif\0\0) or XMP (http://ns.adobe.com/xap/)
                if marker == 0xE1:
                    if seg[:6] in (b"Exif\x00\x00", b"Exif\x00", b"Exif"):
                        # TIFF block: find Software tag via IFD0 (tag 0x0131) rough scan
                        out_parts.append(_tiff_software_text(seg))
                    elif b"xmp" in seg[:40].lower() or seg.lstrip(b"\x00").startswith(b"http"):
                        out_parts.append(seg.decode("utf-8", "ignore"))
                pos += 2 + seg_len
        # --- WebP: RIFF / V8 file, look for EXIF/XMP/VP8X metadata chunks ---
        elif ext in ("webp", "gif") and data[:4] == b"RIFF":
            out_parts.append(_riff_text(data))
    except Exception as e:
        print(f"[image_metadata_text] ({ext}): {e}")
    return " ".join(out_parts)


def _tiff_software_text(seg: bytes) -> str:
    """Best-effort scan of a JPEG EXIF TIFF header for a Software tag (0x0131)."""
    try:
        if len(seg) < 14:
            return ""
        endian = seg[6:8]
        if endian not in (b"II", b"MM"):
            return ""
        e = "<" if endian == b"II" else ">"
        import struct
        # APP1 seg = b"Exif\x00\x00" + TIFF. TIFF header: endian(2) magic(2) IFD-offset(4).
        # IFD offset lives at TIFF byte 4-7 == seg[10:14] (base=6).
        base = 6
        off = struct.unpack(e + "I", seg[10:14])[0]
        ifd_off = base + off
        if ifd_off + 2 > len(seg):
            return ""
        (n,) = struct.unpack(e + "H", seg[ifd_off:ifd_off + 2])
        for i in range(n):
            entry = ifd_off + 2 + i * 12
            if entry + 12 > len(seg):
                break
            (tag,) = struct.unpack(e + "H", seg[entry:entry + 2])
            (typ,) = struct.unpack(e + "H", seg[entry + 2:entry + 4])
            (cnt,) = struct.unpack(e + "I", seg[entry + 4:entry + 8])
            if tag == 0x0131:  # Software
                val_off = entry + 8
                if typ == 2 and cnt > 0:  # ASCII
                    val = seg[val_off:val_off + 4] if cnt <= 4 else seg[base + struct.unpack(e + "I", seg[val_off:val_off + 4])[0]:]
                    return bytes(val[:cnt]).decode("latin-1", "ignore").rstrip("\x00 ")
                break
    except Exception:
        pass
    return ""


def _riff_text(data: bytes) -> str:
    """Pull EXIF/XMP text from a WebP/RIFF container."""
    try:
        out = []
        pos = 12  # skip 'RIFF' + size + 'WEBP'
        while pos + 8 <= len(data):
            chunk = data[pos:pos + 4]
            (clen,) = __import__("struct").unpack("<I", data[pos + 4:pos + 8])
            body = data[pos + 8:pos + 8 + clen]
            if chunk in (b"EXIF", b"XMP "):
                out.append(body.decode("utf-8", "ignore"))
            pos += 8 + clen + (clen & 1)
    except Exception:
        pass
    return " ".join(out)


_CAMERA_MAKE_TAGS = (0x010F, 0x0110)   # Make / Model
_CAMERA_DATE_TAGS = (0x0132,)          # DateTime â€” a reliable camera capture marker


def _tiff_camera_provenance(seg: bytes) -> bool:
    """Does this EXIF TIFF block look like it was written by a real camera /
    phone (a Make, a Model, or a DateTime)? Non-camera producers (AI generators,
    web scrubbers) almost never fill these in. Software tags are deliberately NOT
    trusted here â€” an editor like Photoshop writes Software="Adobe Photoshop", so
    counting that as "camera provenance" would let a doctored image pass clean."""
    try:
        if len(seg) < 14:
            return False
        e = "<" if seg[6:8] == b"II" else ">"
        if seg[6:8] not in (b"II", b"MM"):
            return False
        import struct
        base = 6
        ifd_off = base + struct.unpack(e + "I", seg[10:14])[0]
        (n,) = struct.unpack(e + "H", seg[ifd_off:ifd_off + 2])
        for i in range(n):
            entry = ifd_off + 2 + i * 12
            if entry + 12 > len(seg):
                break
            (tag,) = struct.unpack(e + "H", seg[entry:entry + 2])
            (typ,) = struct.unpack(e + "H", seg[entry + 2:entry + 4])
            # Make/Model/DateTime all count as genuine camera provenance.
            if tag in _CAMERA_MAKE_TAGS and typ == 2:
                return True
            if tag in _CAMERA_DATE_TAGS and typ == 2:
                return True
        return False
    except Exception:
        return False


def _has_camera_provenance(file_bytes: bytes, ext: str) -> bool:
    """Is there any sign this image was captured by a real device (Make/Model/
    camera EXIF)? Absence is the hallmark of AI-generator or scrubbed exports."""
    if ext in ("jpg", "jpeg", "webp") and file_bytes[:2] == b"\xff\xd8":
        pos = 2
        while pos + 4 <= len(file_bytes):
            if file_bytes[pos] != 0xFF:
                break
            marker = file_bytes[pos + 1]
            (seg_len,) = __import__("struct").unpack(">H", file_bytes[pos + 2:pos + 4])
            if seg_len < 2 or pos + 2 + seg_len > len(file_bytes):
                break
            seg = file_bytes[pos + 4:pos + 2 + seg_len]
            if marker == 0xE1 and seg[:5] in (b"Exif\x00", b"Exif") and _tiff_camera_provenance(seg):
                return True
            pos += 2 + seg_len
        return False
    if ext == "webp" and file_bytes[:4] == b"RIFF":
        import struct
        pos = 12
        while pos + 8 <= len(file_bytes):
            chunk = file_bytes[pos:pos + 4]
            (clen,) = struct.unpack("<I", file_bytes[pos + 4:pos + 8])
            body = file_bytes[pos + 8:pos + 8 + clen]
            if chunk == b"EXIF" and _tiff_camera_provenance(body):
                return True
            pos += 8 + clen + (clen & 1)
        return False
    # PNG / GIF / BMP have no standard camera EXIF â€” a real shot rarely ends up
    # here, so treat absence as "no camera provenance" (suspicious for AI).
    return False


_HAVE_NP = None
def _import_np():
    """Lazy numpy â€” only loaded on the image-verify path so normal requests and
    the serverless cold-start aren't penalised. Returns None if unavailable."""
    global _HAVE_NP
    if _HAVE_NP is None:
        try:
            import numpy as _np
            _HAVE_NP = _np
        except Exception:
            _HAVE_NP = False
    return _HAVE_NP if _HAVE_NP else None


_HAVE_PIL = None
def _import_pil():
    """Lazy Pillow for image trap inject/verify. None if unavailable."""
    global _HAVE_PIL
    if _HAVE_PIL is None:
        try:
            import PIL as _pil
            _HAVE_PIL = _pil
        except Exception:
            _HAVE_PIL = False
    return _HAVE_PIL if _HAVE_PIL else None


def _pixel_forensics(file_bytes: bytes, ext: str):
    """Pixel-level deepfake/AI signal that survives FULLY stripped metadata.

    Two complementary, dependency-cheap tests on a small downscaled patch:
      * JPEG ELA: re-encode at quality ~90 and measure per-tile recompression
        uniformity. Real photos resave with spatially varied error (detail +
        noise); AI images and heavy compression resave almost uniformly.
      * Noise floor: std of the local Laplacian on the luminance patch. Camera
        shots carry sensor noise -> higher, scattered variance; AI/vector /
        over-compressed exports are unnaturally clean/uniform.

    Returns (leaning, reason, ran) where `ran` tells the caller the pixels were
    actually inspected (so a clean read is trustworthy and suppresses the blunt
    "missing metadata" fallback). (None, None, False) means deps/decoding failed
    and we have no pixel opinion. Cost is capped: decode to <=160px wide, once."""
    np = _import_np()
    if np is None:
        return None, None, False
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(file_bytes)).convert("L")
        if img.width == 0 or img.height == 0:
            return None, None, False
        max_w = 160
        if img.width > max_w:
            img = img.resize((max_w, int(img.height * max_w / img.width)))
        a = np.asarray(img, dtype=np.int16)

        # Noise floor via local Laplacian energy.
        g = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.int16)
        lap = np.zeros(a.shape, dtype=np.int16)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                gv = g[dy + 1][dx + 1]
                if gv == 0:
                    continue
                rolled = np.roll(np.roll(a, -dy, axis=0), -dx, axis=1)
                lap += gv * rolled
        noise_std = float(lap.std())

        # Heuristics (conservative, tuned to avoid false-positives on legitimate
        # flat graphics / real photos): real photos carry sensor/compression noise
        # -- their fine (Laplacian) detail is HIGH relative to their gross contrast.
        # AI / oversmoothed output keeps tonal contrast but squeezes out fine noise,
        # so its fine-to-gross RATIO collapses. A flat/solid image has low gross
        # contrast too and is NOT flagged (content floor), avoiding graphic false-pos.
        gross_std = float(np.asarray(a, dtype=np.float32).std())
        fine_noise = noise_std
        ratio = fine_noise / (gross_std + 1e-6)
        content = gross_std > 15.0      # image actually has tonal variation
        suspicious_noise = ratio < 200.0 and fine_noise < 60.0

        # JPEG ELA is the strongest signal: a real camera JPEG re-encodes with
        # spatially VARYING error; AI/heavy compression re-encodes uniformly.
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
            return ("ai", ("Pixel-level scan of the image shows tonal content but "
                           "an unnaturally smooth, low-noise pattern (or a suspiciously "
                           "uniform re-compression error) â€” a hallmark of AI generation "
                           "or heavy automated processing."), True)
        return None, None, True
    except Exception:
        return None, None, False


def forensic_report(file_bytes: bytes, filename: str, trap_found: bool = False,
                    signature_valid: bool = None) -> dict:
    """Inspect file metadata/containers and return a plain-language forensics
    breakdown. Works on PDF, MP3/WAV and MP4/M4A/MOV; other types return a
    clean/unknown read. Returns:
      {
        "leaning": "ai"|"edited"|"clean"|"unknown",
        "tool":    detected tool name or None,
        "ai":      True if an AI generator was detected,
        "edited":  True if an editing app was detected,
        "reasons": [ plain-language human-readable lines, ... ]
      }"""
    ext = (filename or "").lower().split(".")[-1] if "." in (filename or "") else ""
    reasons = []
    leaning = "unknown"
    tool = None
    is_ai = False
    is_edited = False

    producer = None
    container_text = ""

    try:
        from pypdf import PdfReader
        from mutagen.mp4 import MP4
        if ext == "pdf":
            meta = PdfReader(io.BytesIO(file_bytes)).metadata or {}
            producer = " ".join(str(v) for v in [
                meta.get("/Producer"), meta.get("/Creator"),
                meta.get("/Title"), meta.get("/Subject")] if v)
            container_text = producer
        elif ext in ["mp3", "wav"]:
            from mutagen.id3 import ID3
            tags = ID3(io.BytesIO(file_bytes))
            parts = []
            for f in tags.values():
                if hasattr(f, "desc") and f.desc in ("TXXX", "TIT2", "COMM"):
                    parts.append((f.text if hasattr(f, "text") else str(f)))
                elif str(f).startswith("TXXX"):
                    parts.append(str(f))
            container_text = " ".join(str(p) for p in parts)
            if hasattr(tags, "getall"):
                for f in tags.getall("TIT2") + tags.getall("COMM") + tags.getall("TXXX"):
                    if hasattr(f, "text"):
                        container_text += " " + " ".join(str(x) for x in f.text)
        elif ext in ["mp4", "m4a", "mov", "aac"]:
            mp4 = MP4(io.BytesIO(file_bytes))
            keys = ["\xa9too", "\xa9cmt", "\xa9swr", "\xa9nam", "\xa9prd", "Â©too", "com.apple.quicktime.software"]
            container_text = " ".join(str(v) for k in keys
                                      for v in (mp4.get(k) or []))
        elif ext in ("jpg", "jpeg", "png", "webp", "gif", "bmp"):
            # Images rarely print a producer into "metadata" parsers â€” the tool
            # lives in EXIF/XMP/PNG-text/RIFF segments. We read those with stdlib
            # so Canva/AI-upscalers/editors get named instead of a silent "clean".
            container_text = _image_metadata_text(file_bytes, ext)
    except Exception as e:
        print(f"[forensic_report] parse note ({ext}): {e}")
        container_text = ""

    # Pixel-level scan FIRST â€” the most reliable signal for images, superseding
    # the blunt "missing metadata" fallback. Runs for every image; absent deps or
    # undecodable bytes yield (None,None) and we fall back gracefully.
    pixel_ran = False
    confidence = 0.0
    if ext in ("jpg", "jpeg", "png", "webp", "gif", "bmp"):
        pxl_lean, pxl_reason, pixel_ran = _pixel_forensics(file_bytes, ext)
        if pixel_ran and pxl_reason:
            if pxl_lean == "ai":
                is_ai = True
                leaning = "ai"
                confidence = 0.8
                reasons.append(pxl_reason)
        # A clean pixel read suppresses the blunt "missing metadata" lean below.

    # 1) Tool/AI signature scan
    kind, tool, desc, sig_conf = _match_tool(container_text or producer)
    if kind == "ai":
        is_ai = True
        leaning = "ai"
        confidence = max(confidence, sig_conf or 0.9)
        reasons.append(desc + " This means the picture/video may be AI-generated, not a real photo.")
    elif kind == "edited":
        is_edited = True
        leaning = "edited"
        confidence = max(confidence, sig_conf or 0.65)
        reasons.append(desc + " This file has been edited after it was made.")
    elif ext in ("pdf", "mp3", "wav", "mp4", "m4a", "mov", "aac", "jpg", "jpeg", "png", "gif", "webp", "bmp"):
        # No explicit tool tag. For images we trust the pixel scan whenever it
        # actually inspected the pixels: real-but-metadata-free photos read clean,
        # so we DON'T lean AI just for a missing camera trail. The old camera-trail
        # heuristic only fires when pixel forensics is unavailable.
        if ext in ("jpg", "jpeg", "png", "webp", "gif", "bmp"):
            if not pixel_ran and not _has_camera_provenance(file_bytes, ext):
                reasons.append("No camera, editing, or AI labels are embedded, and pixel forensics was not "
                               "available â€” the missing data trail may indicate an AI or heavily-processed image.")
                if leaning == "unknown":
                    leaning = "ai"
                    confidence = max(confidence, 0.55)
            else:
                reasons.append("No editing apps or AI tools were found in this file's hidden labels.")
        else:
            reasons.append("No editing apps or AI tools were found in this file's hidden labels.")
    else:
        reasons.append("This file type has no readable metadata labels to inspect.")

    # 2) Trap cross-check: crypto signature failed but our marker survived.
    if trap_found and signature_valid is False:
        reasons.append("Our invisible safety stamp is still there, but the file's content no longer matches it â€” "
                       "a classic sign that someone edited it after it was officially signed.")
        if leaning == "unknown":
            leaning = "edited"
        confidence = max(confidence, 0.95)

    # 3) Tool summarised on top.
    if is_ai:
        leaning = "ai"
    elif is_edited:
        leaning = "edited"

    return {
        "leaning": leaning,
        "tool": tool,
        "ai": is_ai,
        "edited": is_edited,
        "confidence": confidence,
        "reasons": reasons,
    }

def compute_merkle_root(leaf_hashes: List[str]) -> str:
    if not leaf_hashes: return hashlib.sha256(b"GENESIS").hexdigest()
    current_level = [bytes.fromhex(h) if len(h) == 64 else hashlib.sha256(h.encode()).digest() for h in leaf_hashes]
    while len(current_level) > 1:
        if len(current_level) % 2 != 0: current_level.append(current_level[-1])
        current_level = [hashlib.sha256(current_level[i] + current_level[i + 1]).digest() for i in range(0, len(current_level), 2)]
    return current_level[0].hex()

def anchor_merkle_to_chain(merkle_root: str) -> str:
    if not WEB3_RPC_URL or not WALLET_PRIV_KEY: return f"0xSIMULATED_TX_{hashlib.sha256(merkle_root.encode()).hexdigest()[:40]}"
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(WEB3_RPC_URL))
        account = w3.eth.account.from_key(WALLET_PRIV_KEY)
        tx = {
            'to': account.address, 'value': 0, 'gas': 100000, 'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account.address),
            'data': Web3.to_bytes(text=f"NOCAP_ROOT:{merkle_root}"), 'chainId': w3.eth.chain_id
        }
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=WALLET_PRIV_KEY)
        raw_tx = getattr(signed_tx, "raw_transaction", getattr(signed_tx, "rawTransaction", None))
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        return w3.to_hex(tx_hash)
    except Exception: return "TX_FAILED"

# ==============================================================================
# [ COLUMN 5: FASTAPI SETUP & BASE ROUTES ]
# ==============================================================================

# max_body_size lifts Starlette's default 2MB request cap so authorized signers
# can upload several media files at once (the 413 "Payload Too Large" bug).
# 50 MB in bytes; signs video/photos in a single batch without tripping.
app = FastAPI(title="No Cap Â· Enterprise Provenance Engine", version="12.0",
              max_body_size=50 * 1024 * 1024)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
@limiter.limit("120/minute")
def index(request: Request):
    return FileResponse(os.path.join(STATIC_DIR, "index.html"), headers={"Cache-Control": "no-store"})

@app.post("/api/admin/login")
@limiter.limit("20/minute")
def admin_login(request: Request, credential: str = Form(...)):
    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests
        idinfo = id_token.verify_oauth2_token(credential, google_requests.Request(), GOOGLE_CLIENT_ID, clock_skew_in_seconds=300)
        email = idinfo.get("email")
        if not email or not idinfo.get("email_verified"): raise ValueError("Google did not return a verified email.")
        email = email.strip().lower()

        # Authorization gate â€” the allow/deny is driven by Google Cloud itself,
        # not by a hardcoded Python list (see ALLOWED_DOMAINS / ALLOWED_EMAILS).
        #   * ALLOWED_DOMAINS matches BOTH id_token["hd"] (the hosted Google
        #     Workspace domain â€” the account's domain you manage in Google
        #     Cloud) and the email's own "@domain" suffix (for non-Workspace
        #     accounts). Anyone added to that domain is allowed automatically.
        #   * Exact emails are allow-listed via ALLOWED_EMAILS.
        #   * Super admins always pass so the owner is never locked out.
        allowed = False
        if not is_super_admin(email):
            hd = str(idinfo.get("hd") or "").strip().lower()
            suffix = email.split("@", 1)[1] if "@" in email else ""
            if (hd and hd in ALLOWED_DOMAINS) or (suffix in ALLOWED_DOMAINS):
                allowed = True
            elif email in ALLOWED_EMAILS:
                allowed = True
        else:
            allowed = True

        if not allowed:
            raise ValueError("ACCESS DENIED: your Google account is not authorized to use this system.")

        with get_db() as db: get_or_create_signer_identity(db, email, idinfo.get("name"))
        res = JSONResponse(content={"status": "SUCCESS", "admin": email})
        res.set_cookie(key="nischay_session", value=make_session_token(email), httponly=True, secure=os.getenv("VERCEL") == "1", samesite="lax", max_age=86400)
        return res
    except Exception:
        raise HTTPException(401, "AUTH FAILED: your Google credential could not be verified.")

@app.post("/api/admin/logout")
@limiter.limit("20/minute")
def admin_logout(request: Request):
    res = JSONResponse(content={"status": "LOGGED_OUT"})
    res.delete_cookie("nischay_session")
    return res

@app.get("/api/admin/me")
@limiter.limit("120/minute")
def check_auth_status(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=admin).first()
    designation = (identity.designation if identity else None) or None
    institution = (identity.institution if identity else None) or None
    pending = bool(identity and (not designation or not institution))
    return {"status": "AUTHENTICATED", "admin": admin, "name": identity.name if identity else admin,
            "designation": designation, "institution": institution, "pending_approval": pending,
            "is_super_admin": is_super_admin(admin)}

@app.post("/api/admin/assign_role")
@limiter.limit("20/minute")
def assign_role(request: Request, target_email: str = Form(...), designation: str = Form(...), institution: str = Form(...), admin: str = Depends(get_current_admin)):
    """Super-admin only: approve/assign a signer's post & institution. Signers cannot self-assign."""
    if not is_super_admin(admin): raise HTTPException(403, "Super-admin clearance required.")
    target = target_email.strip().lower()
    desig, inst = designation.strip()[:150], institution.strip()[:150]
    if not target or not desig or not inst: raise HTTPException(400, "Target signer, post and institution are required.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=target).first()
        if not identity: raise HTTPException(404, "Signer not found.")
        identity.designation, identity.institution = desig, inst
        db.commit()
    return {"status": "ROLE_ASSIGNED", "email": target, "designation": desig, "institution": inst}

# ==============================================================================
# [ COLUMN 6: SIGNING, BROADCASTS & VERIFICATION ENGINE ]
# ==============================================================================

# --- Shared helpers used by every signing/broadcasting endpoint. Keeping the
#     role guard and key decryption in one place means a signer's privileges are
#     impossible to bypass by calling a "less guarded" route. ---

def _safe_filename(name: str) -> str:
    """Strip any path components a client might smuggle into a filename, so
    download names and ZIP entries can never escape into directories. Binary
    control chars and quotes are removed too: the result is spliced into
    Content-Disposition header values, where CR/LF would allow header
    injection and a raw `"` would break the quoted filename."""
    cleaned = (name or "file").replace("\\", "/").split("/")[-1].strip()
    cleaned = re.sub(r"[\x00-\x1f\x7f\"']", "", cleaned)
    return cleaned or "file"

_IMAGE_EXT = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp"}
_VIDEO_EXT = {".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime", ".ogg": "video/ogg", ".m4v": "video/x-m4v"}

def _guess_media_type(name: str) -> str:
    ext = os.path.splitext((name or "").lower())[1]
    return _IMAGE_EXT.get(ext) or _VIDEO_EXT.get(ext) or "application/octet-stream"

def _is_broadcast_media(mime: str) -> bool:
    return (mime or "").startswith("image/") or (mime or "").startswith("video/")

def load_active_signer(db, admin: str):
    """Resolve + authorise a signer for a signing request.

    Returns (identity, institution, role, private_key). Raises 403 unless the
    caller is a registered, non-revoked signer whose post & institution were
    approved by a super admin â€” signing with a self-typed title is impossible."""
    identity = db.query(SignerIdentity).filter_by(email=admin).first()
    if not identity or identity.is_revoked:
        raise HTTPException(403, "Invalid or revoked identity.")
    institution = (identity.institution or "").strip()
    role = (identity.designation or "").strip()
    if not institution or not role:
        raise HTTPException(403, "Role pending: a super admin must approve your post & institution before you can sign.")
    priv_key = serialization.load_pem_private_key(
        decrypt_vault_key(identity.enc_priv_key, identity.email), password=None)
    return identity, institution, role, priv_key

def insert_block_once(db, **fields) -> bool:
    """Append a ledger block unless the artifact was already signed. file_hash
    is UNIQUE at the DB level, so re-signing identical bytes is an atomic
    no-op instead of a select-then-insert race.

    Returns True when a NEW block was written, False when the hash already
    existed (dup). The INSERT runs inside the session's own transaction; the
    CALLER commits so sign/broadcast flows persist exactly as add()+commit()."""
    if _IS_SQLITE:
        # Select-then-insert is NOT atomic: two concurrent re-signs of the same
        # bytes both pass the check and the loser dies on the UNIQUE constraint
        # at commit. Run the check+insert inside a SAVEPOINT so the loser only
        # loses the savepoint (returns "already exists") instead of poisoning
        # the caller's whole session transaction.
        try:
            with db.begin_nested():
                if db.query(LedgerBlock).filter_by(file_hash=fields["file_hash"]).first():
                    return False
                db.add(LedgerBlock(**fields))
        except IntegrityError:
            return False
        return True
    result = db.execute(pg_insert(LedgerBlock).values(**fields).on_conflict_do_nothing(index_elements=["file_hash"]))
    return (result.rowcount or 0) > 0

@app.post("/api/sign_text")
@limiter.limit("40/minute")
async def sign_text_notice(request: Request, message: str = Form(...), broadcast_title: str = Form("Emergency Notice"), urgency_level: str = Form("HIGH"),
                           media: UploadFile = File(None), admin: str = Depends(get_current_admin)):
    """Signs an Emergency Broadcast (text + optional image/video) and returns a
    verifiable JSON receipt.

    Returns plain JSON (no forced attachment download) so the client never has
    to read a response body twice. The ECDSA sign is ~1ms; Neon round trips are
    the only cost, handled in a threadpool and deduped by the unique index."""
    clean_msg = message.strip()
    if not clean_msg:
        raise HTTPException(400, "Message body empty.")
    if len(clean_msg) > 5000:
        raise HTTPException(400, "Message too long (5,000 character cap).")
    if urgency_level not in {"CRITICAL", "HIGH", "ADVISORY"}:
        raise HTTPException(400, "Invalid urgency level.")
    broadcast_title = broadcast_title.strip()[:120] or "Emergency Notice"

    media_bytes = None
    media_type = None
    media_name = None
    if media and media.filename:
        media_bytes = await media.read()
        if media_bytes:
            media_name = _safe_filename(media.filename)
            media_type = media.content_type or _guess_media_type(media_name)
            if not _is_broadcast_media(media_type):
                raise HTTPException(400, "Attached media must be an image or video file.")

    # The signed payload binds the message text AND any embedded media, so a
    # swapped-out image/video cannot sneak past verification.
    payload = clean_msg.encode("utf-8") + (b"\x00MEDIA\x00" + media_bytes if media_bytes else b"")
    text_hash = hashlib.sha256(payload).hexdigest()

    result = await run_in_threadpool(
        _sign_text_core, admin, clean_msg, broadcast_title, urgency_level, text_hash,
        media_bytes, media_type, media_name,
    )
    return JSONResponse(result)

def _sign_text_core(admin: str, clean_msg: str, broadcast_title: str, urgency_level: str, text_hash: str,
                    media_bytes, media_type, media_name) -> dict:
    """Synchronous core of the broadcast (sign + provenance insert). Kept out of
    the event loop so a slow Neon round trip never freezes the whole app."""
    with get_db() as db:
        identity, institution, role, priv_key = load_active_signer(db, admin)
        timestamp = now_utc()
        sig_hex = f"hybrid:{priv_key.sign(text_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()}"

        receipt = {
            "version": "nocap-v2-emergency", "title": broadcast_title, "urgency": urgency_level, "content": clean_msg,
            "file_hash": text_hash, "signature": sig_hex, "timestamp": timestamp,
            "signer": {"name": identity.name, "institution": institution, "designation": role},
        }
        if media_bytes:
            receipt["media"] = {
                "name": media_name,
                "type": media_type,
                "sha256": hashlib.sha256(media_bytes).hexdigest(),
            }
        cid = upload_receipt_to_ipfs(receipt)

        # Unique-hash dedup: active notices re-sign as a no-op. A *retracted*
        # notice resurrects only when its ORIGINAL issuer re-issues the exact
        # text â€” the original pubkey is embedded in the row, so anyone else's
        # signature would make verification report PROVEN_FAKE.
        existing = db.query(LedgerBlock).filter_by(file_hash=text_hash).first()
        if existing and existing.notice_deleted and (existing.signer_email or "").strip().lower() == admin.strip().lower():
            existing.notice_deleted = False
            existing.notice_content = clean_msg
            existing.timestamp = timestamp
            existing.sig_hex = sig_hex
            existing.ipfs_cid = cid
            existing.notice_media_type = media_type
            existing.notice_media_name = media_name
            existing.notice_media_data = media_bytes
            persisted = True
        elif existing:
            persisted = False
        else:
            insert_block_once(
                db,
                signer_email=identity.email, signer_name=identity.name,
                signer_institution=institution, signer_designation=f"EMERGENCY ({urgency_level})",
                filename=f"NOTICE_{broadcast_title[:20]}.json", file_hash=text_hash,
                sig_hex=sig_hex, timestamp=timestamp, ipfs_cid=cid,
                notice_content=clean_msg,
                notice_media_type=media_type,
                notice_media_name=media_name,
                notice_media_data=media_bytes,
            )
            persisted = True
        db.commit()
    return {"receipt": receipt, "ipfs_cid": cid, "ledger_persisted": persisted, "ledger_hash": text_hash}

@app.post("/api/sign")
@limiter.limit("60/minute")
async def sign_media(request: Request, files: List[UploadFile] = File(...), admin: str = Depends(get_current_admin)):
    if not files:
        raise HTTPException(400, "No files.")

    with get_db() as db:
        identity, institution, role, priv_key = load_active_signer(db, admin)
        signer_label = f"{identity.name} ({role}, {institution})"
        timestamp, ready = now_utc(), []

        for f in files:
            raw = await f.read()
            if not raw:
                continue
            safe_name = _safe_filename(f.filename)
            trapped = _sign_single_file(db, priv_key, signer_label, identity, institution,
                                        role, raw, safe_name, timestamp)
            ready.append({"name": f"signed_{safe_name}", "bytes": trapped})

        db.commit()  # persist every ledger block written above (see insert_block_once)
        if not ready:
            raise HTTPException(400, "No content to sign.")

        if len(ready) == 1:
            return Response(ready[0]["bytes"], media_type="application/octet-stream",
                            headers={"Content-Disposition": f'attachment; filename="{ready[0]["name"]}"'})
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            for item in ready:
                zf.writestr(item["name"], item["bytes"])
        return Response(mem_zip.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="signed_batch.zip"'})

def _sign_single_file(db, priv_key, signer_label, identity, institution, role,
                      raw: bytes, safe_name: str, timestamp: str) -> bytes:
    """Core signing of ONE artifact: trap-inject + two ECDSA signatures + IPFS
    receipt + ledger block. Returns the trapped (signed) bytes. Shared by
    /api/sign (in-memory) and /api/sign_complete (chunked reassembly)."""
    raw_hash = hashlib.sha256(raw).hexdigest()
    sig_hex = f"hybrid:{priv_key.sign(raw_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()}"
    trapped = inject_media_trap(raw, safe_name, signer_label, sig_hex, timestamp)
    final_hash = hashlib.sha256(trapped).hexdigest()
    final_sig = f"hybrid:{priv_key.sign(final_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()}"
    cid = upload_receipt_to_ipfs({"filename": safe_name, "file_hash": final_hash,
                                  "signature": final_sig, "issuer": signer_label,
                                  "timestamp": timestamp})
    insert_block_once(
        db,
        signer_email=identity.email, signer_name=identity.name,
        signer_institution=institution, signer_designation=role,
        filename=safe_name, file_hash=final_hash, sig_hex=final_sig,
        timestamp=timestamp, ipfs_cid=cid,
    )
    return trapped

_CHUNK_SESSION_CAP = 64 * 1024 * 1024  # max buffered bytes per chunk session
_CHUNK_SESSION_TTL_HOURS = 2  # orphaned chunks older than this are swept


def _guard_chunk_session(db, session_id: str, incoming_len: int) -> None:
    """Bound one chunk session's buffered storage and sweep orphaned chunks.

    Shared by /api/sign_chunk (authed) and /api/verify_chunk (public): no
    caller is obliged to ever call *complete, so without the cap + sweep an
    abandoned session could grow the PendingUpload table without bound.
    Raises HTTPException(400) when the session would exceed the cap."""
    used = db.query(func.coalesce(func.sum(func.length(PendingUpload.data)), 0)) \
        .filter_by(session_id=session_id).scalar() or 0
    if used + incoming_len > _CHUNK_SESSION_CAP:
        raise HTTPException(400, f"Chunk session exceeds the {_CHUNK_SESSION_CAP // (1024 * 1024)} MB storage cap.")
    stale_cutoff = (datetime.now(timezone.utc) - timedelta(hours=_CHUNK_SESSION_TTL_HOURS)) \
        .strftime("%Y-%m-%d %H:%M:%S UTC")
    db.query(PendingUpload).filter(PendingUpload.created_at < stale_cutoff) \
        .delete(synchronize_session=False)

@app.post("/api/sign_chunk")
@limiter.limit("120/minute")
async def sign_chunk(request: Request, chunk: UploadFile = File(...), session_id: str = Form(...),
                     chunk_index: int = Form(...), total_chunks: int = Form(...),
                     filename: str = Form("file"), admin: str = Depends(get_current_admin)):
    """Receive one slice of a large file for chunked signing. Each chunk request
    stays well under Vercel's ~4.4MB body cap. Chunks are persisted to Postgres
    (NOT memory) so instance recycling between requests is harmless."""
    data = await chunk.read()
    if not data:
        raise HTTPException(400, "Empty chunk.")
    if not (0 <= chunk_index < total_chunks):
        raise HTTPException(400, "Invalid chunk index.")
    if len(data) > 4 * 1024 * 1024:
        raise HTTPException(400, "Chunk too large (4 MB cap).")

    with get_db() as db:
        # Auth is enforced on EVERY chunk so an unapproved caller can't prefill.
        # Cap storage per session and sweep orphaned chunks (a signer is not
        # obliged to ever call *complete), mirroring the public verify_chunk guard.
        _guard_chunk_session(db, session_id, len(data))
        db.query(PendingUpload).filter_by(session_id=session_id, chunk_index=chunk_index).delete()
        db.add(PendingUpload(
            session_id=session_id, chunk_index=chunk_index, total_chunks=total_chunks,
            filename=_safe_filename(filename), content_type=chunk.content_type or None,
            data=data, created_at=now_utc()))
        db.commit()
    return {"ok": True, "session_id": session_id, "chunk_index": chunk_index,
            "received_bytes": len(data)}

@app.post("/api/sign_complete")
@limiter.limit("60/minute")
async def sign_complete(request: Request, session_id: str = Form(...),
                        admin: str = Depends(get_current_admin)):
    """Reassemble a chunked upload, run the real sign pipeline on the whole file,
    record one ledger block, and return the signed artifact. Temp chunks are
    deleted after use."""
    with get_db() as db:
        identity, institution, role, priv_key = load_active_signer(db, admin)
        signer_label = f"{identity.name} ({role}, {institution})"

        rows = (db.query(PendingUpload).filter_by(session_id=session_id)
                .order_by(PendingUpload.chunk_index).all())
        if not rows:
            raise HTTPException(400, "No chunks found for this session.")
        total = rows[0].total_chunks
        if len(rows) != total:
            raise HTTPException(400, f"Incomplete upload: got {len(rows)}/{total} chunks.")

        raw = b"".join(r.data for r in rows)
        safe_name = _safe_filename(rows[0].filename)
        timestamp = now_utc()

        trapped = _sign_single_file(db, priv_key, signer_label, identity, institution,
                                    role, raw, safe_name, timestamp)
        try:
            db.commit()
        finally:
            # Chunk rows are temp by design: sweep them even when the sign
            # commit above raised, so a failed large upload never orphans MBs
            # of PendingUpload rows. rollback() is a no-op on a clean session
            # and clears failed state otherwise, so the delete can always run.
            db.rollback()
            try:
                db.query(PendingUpload).filter_by(session_id=session_id).delete()
                db.commit()
            except Exception:
                pass

        return Response(trapped, media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="signed_{safe_name}"'})

@app.post("/api/verify_chunk")
@limiter.limit("120/minute")
async def verify_chunk(request: Request, chunk: UploadFile = File(...), session_id: str = Form(...),
                       chunk_index: int = Form(...), total_chunks: int = Form(...),
                       filename: str = Form("file")):
    """Receive one slice of a large file for chunked verification. Public, like
    /api/verify, so anyone can run a forensic check on a big media file without
    tripping Vercel's ~4.4MB body cap. Chunks buffer in Postgres, not memory."""
    data = await chunk.read()
    if not data:
        raise HTTPException(400, "Empty chunk.")
    if not (0 <= chunk_index < total_chunks):
        raise HTTPException(400, "Invalid chunk index.")
    if len(data) > 4 * 1024 * 1024:
        raise HTTPException(400, "Chunk too large (4 MB cap).")

    with get_db() as db:
        # verify_chunk is PUBLIC (anyone can run a forensic check), so bound how
        # much storage one session may claim and sweep orphans — no caller is
        # obliged to ever call *complete.
        _guard_chunk_session(db, session_id, len(data))
        db.query(PendingUpload).filter_by(session_id=session_id, chunk_index=chunk_index).delete()
        db.add(PendingUpload(
            session_id=session_id, chunk_index=chunk_index, total_chunks=total_chunks,
            filename=_safe_filename(filename), content_type=chunk.content_type or None,
            data=data, created_at=now_utc()))
        db.commit()
    return {"ok": True, "session_id": session_id, "chunk_index": chunk_index,
            "received_bytes": len(data)}

@app.post("/api/verify_complete")
@limiter.limit("60/minute")
async def verify_complete(request: Request, session_id: str = Form(...),
                          client_hash: str = Form(None)):
    """Reassemble a chunked verification upload and run the SAME forensic verdict
    as /api/verify on the whole file. Temp chunks are deleted after use.

    The client can send the SHA-256 of the ENTIRE file as client_hash. That hash
    is the ledger lookup key, so we DON'T need to pull every byte back across the
    network to reach the verdict â€” forensics only read a bounded header/sample
    window (metadata tags and pixel cues live at the start of the file)."""
    with get_db() as db:
        # Existence + completeness check WITHOUT hydrating every chunk's bytes.
        meta = (db.query(PendingUpload.filename, PendingUpload.total_chunks)
                .filter_by(session_id=session_id)
                .order_by(PendingUpload.chunk_index)
                .first())
        if not meta:
            raise HTTPException(400, "No chunks found for this session.")
        total = meta.total_chunks
        have = db.query(PendingUpload.chunk_index).filter_by(session_id=session_id).count()
        if have != total:
            raise HTTPException(400, f"Incomplete upload: got {have}/{total} chunks.")

        safe_name = _safe_filename(meta.filename)

        try:
            # Either trust the client's full-file SHA-256 (the ledger/hash lookup key)
            # or fall back to re-assembling everything (small files / no hash sent).
            if client_hash and re.fullmatch(r"[0-9a-fA-F]{64}", client_hash.strip()):
                target_hash = client_hash.strip().lower()
                # Forensics only need the metadata-bearing header + a pixel sample
                # region — not the whole body — so fetch only the FIRST chunk (up to
                # 4MB) rather than pulling every chunk back across the network.
                _SCAN_WINDOW = 2 * 1024 * 1024
                head = db.query(PendingUpload).filter_by(session_id=session_id) \
                    .order_by(PendingUpload.chunk_index).limit(1).first()
                sample = (head.data if head else b"")[:_SCAN_WINDOW]
                has_trap = extract_media_trap(sample, safe_name)
                payload = _verify_bytes(db, sample, safe_name, target_hash, has_trap)
                payload["hash"] = target_hash
            else:
                rows = (db.query(PendingUpload).filter_by(session_id=session_id)
                        .order_by(PendingUpload.chunk_index).all())
                raw = b"".join(r.data for r in rows)
                target_hash = hashlib.sha256(raw).hexdigest()
                has_trap = extract_media_trap(raw, safe_name) if raw else False
                payload = _verify_bytes(db, raw, safe_name, target_hash, has_trap)
                payload["hash"] = target_hash
        finally:
            # Same temp-row guarantee as sign_complete: _verify_bytes commits
            # its own VerificationLog row, so a raise anywhere above must not
            # orphan this session's chunks.
            db.rollback()
            try:
                db.query(PendingUpload).filter_by(session_id=session_id).delete()
                db.commit()
            except Exception:
                pass
        return payload

async def resolve_verify_input(file, client_hash: str, filename: str):
    """Normalise any verify request into (raw_bytes, display_name, target_hash).

    A JSON receipt carries its authoritative file_hash inside it (that's the
    whole point of the receipt), so that wins over re-hashing the bytes.

    client_hash alongside a file is an explicit digest ATTESTATION: used by the
    web client for LARGE files to send only a bounded forensic sample (first
    ~2MB) yet check the FULL-file hash against the ledger. Same trust model as a
    .json receipt â€” the digest is what was signed, so it is the lookup key."""
    if file is not None:
        raw = await file.read()
        name = _safe_filename(file.filename) or filename or "file"
        receipt_hash = None
        if name.lower().endswith(".json"):
            try:
                receipt_hash = json.loads(raw.decode()).get("file_hash")
            except Exception:
                receipt_hash = None
        if client_hash:
            client_hash = client_hash.strip()
            if not re.fullmatch(r"[0-9a-fA-F]{64}", client_hash):
                raise HTTPException(400, "client_hash must be a 64-character SHA-256 hex digest.")
            # Explicit digest attestation (large-file sample path) outranks a
            # server re-hash, matching the .json receipt semantics.
            target_hash = client_hash.lower()
        else:
            target_hash = receipt_hash or hashlib.sha256(raw).hexdigest()
        return raw, name, target_hash

    if client_hash:
        client_hash = client_hash.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", client_hash):
            raise HTTPException(400, "client_hash must be a 64-character SHA-256 hex digest.")
        return b"", filename or "hash_query", client_hash

    raise HTTPException(400, "Provide media, hash, or text.")


@app.post("/api/report")
@limiter.limit("30/minute")
def report_forgery(request: Request, file_hash: str = Form(...)):
    """Community "Report Forgery" â€” bumps the flag_count on a signed block so the
    trust team can see a file drew repeat complaints. Idempotent enough for a
    simple counter; the hash stays a pure identity key. Public & rate-limited."""
    fh = file_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fh):
        raise HTTPException(400, "Invalid ledger hash.")
    with get_db() as db:
        blk = db.query(LedgerBlock.id).filter_by(file_hash=fh).first()
        if not blk:
            raise HTTPException(404, "No signed record matches that hash.")
        # Atomic increment: a read-modify-write here loses reports when two
        # officers flag the same hash concurrently.
        db.query(LedgerBlock).filter_by(file_hash=fh).update(
            {LedgerBlock.flag_count: func.coalesce(LedgerBlock.flag_count, 0) + 1},
            synchronize_session=False)
        db.commit()
        new_count = db.query(LedgerBlock.flag_count).filter_by(file_hash=fh).scalar() or 0
        return {"ok": True, "file_hash": fh, "flag_count": new_count,
                "message": "Report recorded. Thanks for keeping the record honest."}


@app.post("/api/verify")
@limiter.limit("120/minute")
async def verify_media(request: Request, file: UploadFile = None, client_hash: str = Form(None), filename: str = Form("file"), raw_text: str = Form(None)):
    if raw_text and raw_text.strip():
        # Broadcast path: the alert text itself is the hashed, signed artifact.
        raw = raw_text.strip().encode("utf-8")
        display_name = "emergency_broadcast.txt"
        target_hash = hashlib.sha256(raw).hexdigest()
        has_trap = False
    else:
        raw, display_name, target_hash = await resolve_verify_input(file, client_hash, filename)
        # A forensic trap can only exist on media that passed through our
        # signer, so one on a hash outside the ledger is proof of tampering.
        has_trap = extract_media_trap(raw, display_name) if raw else False

    with get_db() as db:
        return _verify_bytes(db, raw, display_name, target_hash, has_trap)


def _verify_bytes(db, raw: bytes, display_name: str, target_hash: str,
                  has_trap: bool) -> dict:
    """Run the full forensic verdict on raw bytes and return the JSON payload.
    Shared by /api/verify and the chunked /api/verify_complete."""
    def log_and_return(verdict, msg, signer=None, tx_hash=None, retracted=False,
                       signature_valid=None, block=None, identity=None):
        # Plain, layman-first headline + one-line guidance per verdict.
        # "How to read this for a normal person" wording, no jargon.
        copy = {
            "AUTHENTIC": {
                "headline": "THIS FILE IS REAL",
                "guidance": "The file matches its official signature. Nobody has edited it - you can trust it.",
            },
            "PROVEN_FAKE": {
                "headline": "THIS FILE IS A FORGERY",
                "guidance": "This file was changed after it was officially signed. Do NOT trust or share it.",
            },
            "REVOKED": {
                "headline": "THIS FILE IS VOID",
                "guidance": "The official source pulled back their permission, so this file is no longer valid.",
            },
            "UNSIGNED": {
                "headline": "CANNOT BE TRUSTED",
                "guidance": "No official source ever signed this. Treat it as unofficial unless checked elsewhere.",
            },
        }[verdict]

        # Self-contained ledger receipt embedded in the verdict so the page can
        # build a scannable verification cert (hash + signature + issuer pubkey
        # + timestamp + anchors) without a second round-trip.
        ledger_meta = None
        if block is not None:
            ledger_meta = {
                "hash": block.file_hash,
                "filename": block.filename,
                "signature": block.sig_hex,
                "signed_at": block.timestamp,
                "merkle_root": block.merkle_root,
                "ipfs_cid": block.ipfs_cid,
                "tx_hash": block.tx_hash,
                "retracted": bool(block.notice_deleted),
                "signer_name": block.signer_name,
                "signer_institution": block.signer_institution,
                "signer_designation": block.signer_designation,
                "issuer_pubkey": identity.pub_key if identity is not None else None,
            }

        # Run metadata + container forensics and add the plain reasons.
        report = forensic_report(raw, display_name, trap_found=has_trap,
                                 signature_valid=signature_valid) if raw else {
            "leaning": "unknown", "tool": None, "ai": False, "edited": False,
            "confidence": 0.0, "reasons": ["No file content to inspect."],
        }

        # Partial-content check: the client may attach a full-file SHA-256 and
        # send only a bounded sample (large-media path). When the bytes actually
        # received do NOT match the claimed digest, the verdict is grounded on
        # the digest (the signed artifact) while forensics only saw a sample â€”
        # surface that honestly instead of pretending the whole file was read.
        partial_check = bool(raw) and hashlib.sha256(raw).hexdigest() != target_hash

        # ---- Model-based AI detection (images only). -------------------------
        # Runs the active detector (heuristic / Sightengine / self-hosted ViT),
        # never raises, and reports the confidence + latency for the analytics
        # graph. Non-image files skip it (detection only makes sense on media).
        ai_det = {"ran": False, "ai_suspected": False, "ai_score": 0,
                  "model": None, "provider": None, "explanation": "No image to analyse.",
                  "latency_ms": 0}
        _ext = (display_name or "").lower().rsplit(".", 1)[-1] if "." in (display_name or "") else ""
        if raw and _ext in ("jpg", "jpeg", "png", "webp", "gif", "bmp"):
            try:
                ai_det = detect_image(raw, display_name)
                if not ai_det.get("explanation"):
                    ai_det["explanation"] = explain(ai_det)
            except Exception:
                ai_det = {"ran": False, "ai_suspected": False, "ai_score": 0,
                          "model": None, "provider": None,
                          "explanation": "AI detection is unavailable for this file right now.",
                          "latency_ms": 0}
            # If a paid cloud backend ran, tally its operations so the quota
            # display stays honest. Fail-open: this never breaks the verdict.
            if ai_det.get("provider") == "sightengine":
                try:
                    _used = int((ai_det.get("raw") or {}).get("operations_used", 0))
                    record_sightengine_usage(_used)
                except Exception:
                    pass

        # An unsigned file that forensics flag as AI-made or edited is NOT a
        # neutral unknown â€” it is a likely forgery and should surface as that.
        # Promote: UNSIGNED + strong AI/edited/trap signal => PROVEN_FAKE.
        lean_flag = False
        warned = False
        if verdict == "UNSIGNED" and (report["ai"] or report["edited"] or has_trap):
            verdict = "PROVEN_FAKE"
            lean_flag = True
            msg = ("FORGERY: no authentic signature and the file looks AI-made or edited."
                   if not has_trap else
                   "FORGERY: our invisible safety stamp was altered after signing.")
            copy = {
                "headline": "THIS FILE IS A FORGERY",
                "guidance": ("This file is not a genuine signed original â€” it is either AI-generated, edited "
                             "after creation, or tampered with. Do NOT trust or share it."),
            }
        # A signature CAN be genuine yet the signed CONTENT is AI-made/edited.
        # We can't call a file that truly matches its signature a fake, but we
        # must never let "THIS FILE IS REAL" hide an AI/edited label either.
        if verdict == "AUTHENTIC" and (report["ai"] or report["edited"]):
            warned = True
            copy = {
                "headline": "SIGNED, BUT POSSIBLY AI/EDITED",
                "guidance": ("The signature is genuine (this exact file was officially signed), but the content "
                             "carries an AI-generation or editing marker. It is authentic-but-suspicious â€” "
                             "confirm with the issuer what it really is."),
            }
        if verdict == "PROVEN_FAKE":
            copy["headline"] = "THIS FILE IS A FORGERY"

        db.add(VerificationLog(file_hash=target_hash, status=verdict, timestamp=now_utc(),
                               detection_ms=ai_det.get("latency_ms", 0),
                               detection_provider=ai_det.get("provider")))
        db.commit()
        # A new verification changed every aggregate the analytics dashboard
        # shows — drop the cached tallies so the next page view recomputes.
        _invalidate_analytics()
        return {"verdict": verdict, "message": msg, "hash": target_hash, "filename": display_name,
                "signer": signer, "tx_hash": tx_hash, "retracted": retracted,
                "headline": copy["headline"], "guidance": copy["guidance"],
                "forensic_leaning": report["leaning"], "forensic_tool": report["tool"],
                "forensic_confidence": report["confidence"],
                "ai_detection": ai_det,
                "ai_score": ai_det.get("ai_score", 0),
                "ai_model": ai_det.get("model"),
                "ai_provider": ai_det.get("provider"),
                "ai_explanation": ai_det.get("explanation"),
                "ai_suspected": report["ai"], "edited_suspected": report["edited"],
                "likely_forged": lean_flag,
                "forgery_warned": warned,
                "partial_check": partial_check,
                "reasons": report["reasons"],
                "ledger": ledger_meta,
                "blockchain_explorer": f"{BLOCKCHAIN_EXPLORER_URL}{tx_hash}" if tx_hash else None}

    block = db.query(LedgerBlock).filter_by(file_hash=target_hash).first()
    if not block:
        verdict = "PROVEN_FAKE" if has_trap else "UNSIGNED"
        msg = ("FORENSIC TRAP TRIGGERED: Metadata detected but binary altered. DEEPFAKE."
               if has_trap else "Hash not found in ledger.")
        return log_and_return(verdict, msg,
                              signature_valid=False if has_trap else None)

    signer_info = {"name": block.signer_name, "institution": block.signer_institution, "designation": block.signer_designation}
    identity = db.query(SignerIdentity).filter_by(email=block.signer_email).first()
    # Orphaned/revoked signer (e.g. a block left behind by a decommissioned
    # identity) must never 500 â€” the honest verdict is that the key is gone.
    if not identity or identity.is_revoked or block.is_revoked:
        return log_and_return("REVOKED", f"Key belonging to {block.signer_name} revoked.",
                              signer=signer_info, tx_hash=block.tx_hash,
                              block=block, identity=identity)

    try:
        parts = block.sig_hex.split(":")
        pub_key = serialization.load_pem_public_key(identity.pub_key.encode())
        pub_key.verify(bytes.fromhex(parts[1] if len(parts) > 1 else block.sig_hex),
                       target_hash.encode(), ec.ECDSA(hashes.SHA256()))
        return log_and_return("AUTHENTIC",
                              ("Verified. Signed by " + block.signer_name + ".") +
                              (" (notice retracted by issuing authority)." if block.notice_deleted else ""),
                              signer=signer_info, tx_hash=block.tx_hash,
                              retracted=bool(block.notice_deleted),
                              signature_valid=True,
                              block=block, identity=identity)
    except Exception:
        return log_and_return("PROVEN_FAKE", "Signature mismatch. Binary altered.",
                              signer=signer_info, signature_valid=False,
                              block=block, identity=identity)

@app.get("/api/receipt/{file_hash}")
@limiter.limit("120/minute")
def public_receipt(request: Request, file_hash: str):
    """Public ledger receipt lookup â€” fetch the full signed metadata (signature, issuer pubkey, timestamp,
    anchors) for ANY ledger hash without uploading the file. Everything here is
    already public ledger data; no secrets are ever exposed."""
    fh = file_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fh):
        raise HTTPException(400, "Invalid ledger hash.")
    with get_db() as db:
        block = db.query(LedgerBlock).filter_by(file_hash=fh).first()
        if not block:
            return {"found": False, "hash": fh}
        identity = db.query(SignerIdentity).filter_by(email=block.signer_email).first()
        revoked = identity is None or identity.is_revoked or block.is_revoked
        return {
            "found": True,
            "hash": block.file_hash,
            "filename": block.filename,
            "signature": block.sig_hex,
            "signed_at": block.timestamp,
            "merkle_root": block.merkle_root,
            "ipfs_cid": block.ipfs_cid,
            "tx_hash": block.tx_hash,
            "retracted": bool(block.notice_deleted),
            "revoked": revoked,
            "signer_name": block.signer_name,
            "signer_institution": block.signer_institution,
            "signer_designation": block.signer_designation,
            "issuer_pubkey": identity.pub_key if identity is not None else None,
            "blockchain_explorer": f"{BLOCKCHAIN_EXPLORER_URL}{block.tx_hash}" if block.tx_hash else None,
        }

# ==============================================================================
# [ EMERGENCY NOTICE BOARD â€” public feed + authority retraction ]
# ==============================================================================

def _viewer_from_cookies(request: Request) -> str | None:
    """Best-effort resolve of the optional admin session cookie. Public feed
    stays anonymous; only a valid session grants per-row delete permissions."""
    token = request.cookies.get("nischay_session")
    if not token or token.count("::") != 2:
        return None
    email, exp_raw, sig = token.split("::")
    # Same HMAC as make_session_token/get_current_admin; expiry is
    # deliberately NOT enforced here (best-effort viewer, not a gate).
    # NOTE: split into 3 parts — the old rsplit("::", 1) returned "email::exp"
    # as the identity, so owner == viewer NEVER matched and signed-in authors
    # were never offered their per-row delete buttons.
    expected = hmac.new(MASTER_VAULT_KEY, f"{email}::{exp_raw}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return email

def _notice_urgency(designation: str | None) -> str:
    m = re.match(r"EMERGENCY\s*\((.+)\)", designation or "")
    return m.group(1).strip().upper() if m else ""

@app.get("/api/broadcasts")
@limiter.limit("120/minute")
def public_broadcasts(request: Request, limit: int = 25):
    """Public, unauthenticated feed of live official emergency notices."""
    try:
        limit = max(1, min(int(limit), 500))
    except Exception:
        limit = 25
    viewer = (_viewer_from_cookies(request) or "").strip().lower()

    with get_db() as db:
        rows = (
            db.query(LedgerBlock)
            .options(defer(LedgerBlock.notice_media_data))
            .filter(LedgerBlock.signer_designation.like("EMERGENCY%"), LedgerBlock.notice_deleted.is_(False))
            .order_by(LedgerBlock.timestamp.desc())
            .limit(limit)
            .all()
        )
        out = []
        for b in rows:
            owner = (b.signer_email or "").strip().lower()
            is_mine = bool(viewer) and owner == viewer
            out.append({
                "title": re.sub(r"^NOTICE_", "", b.filename or "").replace(".json", "")[:140] or "Emergency Notice",
                "urgency": _notice_urgency(b.signer_designation),
                "content": b.notice_content or "",
                "signer": b.signer_name,
                "institution": b.signer_institution or "Independent",
                "designation": b.signer_designation or "",
                "timestamp": b.timestamp,
                "file_hash": b.file_hash,
                "signature": b.sig_hex,
                "ipfs_cid": b.ipfs_cid or "",
                "media_type": b.notice_media_type or "",
                "media_name": b.notice_media_name or "",
                "has_media": bool(b.notice_media_name or b.notice_media_type),
                "is_mine": is_mine,
                "can_delete": bool(viewer) and (is_mine or is_super_admin(viewer)),
            })
    return {"broadcasts": out, "authed": bool(viewer)}

@app.get("/api/broadcasts/{file_hash}/media")
@limiter.limit("120/minute")
def broadcast_media(request: Request, file_hash: str):
    """Publicly serve the media (image/video) attached to an emergency notice.

    The media bytes are stored alongside the signed notice, so the served file
    is exactly the bytes that were bound into the notice's hash at issue time â€”
    serving it here keeps the board renderable without leaking raw DB blobs."""
    fh = file_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fh):
        raise HTTPException(400, "Invalid ledger hash.")
    with get_db() as db:
        blk = (
            db.query(LedgerBlock)
            .filter(LedgerBlock.file_hash == fh, LedgerBlock.signer_designation.like("EMERGENCY%"),
                    LedgerBlock.notice_deleted.is_(False))
            .first()
        )
        if not blk or not blk.notice_media_data:
            raise HTTPException(404, "No attached media for this notice.")
        data = bytes(blk.notice_media_data)
        media_type = blk.notice_media_type or _guess_media_type(blk.notice_media_name or "")
    return Response(content=data, media_type=media_type,
                    headers={"Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff"})

@app.post("/api/broadcasts/delete")
@limiter.limit("30/minute")
def delete_broadcast(request: Request, file_hash: str = Form(...), admin: str = Depends(get_current_admin)):
    """Retract a live emergency notice. Admins may only retract their own;
    super admins may retract any broadcast."""
    fh = file_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fh):
        raise HTTPException(400, "Invalid ledger hash.")
    with get_db() as db:
        blk = (
            db.query(LedgerBlock)
            .filter(LedgerBlock.file_hash == fh, LedgerBlock.signer_designation.like("EMERGENCY%"))
            .first()
        )
        if not blk:
            raise HTTPException(404, "Broadcast not found.")
        title = blk.filename
        if not is_super_admin(admin) and (blk.signer_email or "").strip().lower() != admin.strip().lower():
            raise HTTPException(403, "You may only retract notices you issued.")
        blk.notice_deleted = True
        db.commit()
    return {"ok": True, "file_hash": fh, "title": title}

# ==============================================================================
# [ COLUMN 7: SYSTEM COMMANDS & WEB3 SYNC ]
# ==============================================================================

@app.post("/api/blockchain/sync")
@limiter.limit("10/minute")
def sync_ledger_to_blockchain(request: Request, admin: str = Depends(get_current_admin)):
    if not is_super_admin(admin):
        raise HTTPException(403, "ACCESS DENIED. Only a super admin may anchor the ledger.")
    with get_db() as db:
        # Blobs deferred: anchoring only needs file_hash (+ writing tx_hash),
        # so never hydrate multi-MB notice_media_data for the whole table.
        unanchored = (db.query(LedgerBlock)
                      .options(defer(LedgerBlock.notice_media_data),
                               defer(LedgerBlock.notice_content))
                      .filter(LedgerBlock.tx_hash.is_(None)).all())
        if not unanchored:
            return {"status": "UP_TO_DATE", "message": "All blocks anchored."}
        m_root = compute_merkle_root([b.file_hash for b in unanchored])
        tx_hash = anchor_merkle_to_chain(m_root)
        for b in unanchored:
            b.tx_hash = tx_hash
            b.merkle_root = m_root
        db.commit()
    return {"status": "SUCCESS", "anchored_blocks_count": len(unanchored), "merkle_root": m_root, "tx_hash": tx_hash}

@app.post("/api/set_pin")
@limiter.limit("20/minute")
def set_pin(request: Request, pin: str = Form(...), admin: str = Depends(get_current_admin)):
    # Storing a malformed PIN would lock the signer out of self-revocation.
    pin = pin.strip()
    if not pin.isdigit() or len(pin) != 5:
        raise HTTPException(400, "PIN must be exactly 5 digits.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=admin).first()
        if not identity:
            raise HTTPException(404, "Signer not found.")
        identity.revoke_pin = pin
        db.commit()
    return {"status": "PIN_SET"}

@app.post("/api/revoke")
@limiter.limit("20/minute")
def revoke(request: Request, target_email: str = Form(...), pin: str = Form(None), admin: str = Depends(get_current_admin)):
    target = target_email.strip().lower()
    if not is_super_admin(admin) and target != admin.strip().lower(): raise HTTPException(403, "ACCESS DENIED.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=target).first()
        if not identity: raise HTTPException(404, "Not found.")
        if not is_super_admin(admin):
            if not pin or len(pin.strip()) != 5: raise HTTPException(400, "Valid 5-digit PIN required.")
            if not identity.revoke_pin: raise HTTPException(403, "No PIN set — call /api/set_pin first.")
            if str(identity.revoke_pin) != str(pin.strip()): raise HTTPException(403, "Incorrect PIN.")
        identity.is_revoked, identity.revoked_at = True, now_utc()
        db.query(LedgerBlock).filter_by(signer_email=identity.email).update({"is_revoked": True})
        db.commit()
    return {"status": "REVOKED"}

@app.post("/api/reinstate")
@limiter.limit("20/minute")
def reinstate(request: Request, target_email: str = Form(...), pin: str = Form(...), admin: str = Depends(get_current_admin)):
    if not is_super_admin(admin): raise HTTPException(403, "Super-admin required.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=target_email.strip().lower()).first()
        if not identity: raise HTTPException(404, "Not found.")
        if identity.revoke_pin and str(identity.revoke_pin) != str(pin.strip()): raise HTTPException(403, "Incorrect PIN.")
        elif not identity.revoke_pin and str(pin.strip()) != "00000": raise HTTPException(403, "Enter 00000 to bypass.")
        identity.is_revoked, identity.revoked_at = False, None
        db.query(LedgerBlock).filter_by(signer_email=identity.email).update({"is_revoked": False})
        db.commit()
    return {"status": "REINSTATED"}

@app.post("/api/rollback")
@limiter.limit("10/minute")
def execute_rollback(request: Request, target_timestamp: str = Form(...), admin: str = Depends(get_current_admin)):
    """Truncate the ledger back to a bound. A malformed or empty timestamp would
    compare lexically against every row and silently delete ALL blocks/logs, so
    reject anything that isn't a real 'YYYY-MM-DD HH:MM:SS UTC' string first."""
    if not is_super_admin(admin): raise HTTPException(403, "ACCESS DENIED.")
    cutoff = (target_timestamp or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC", cutoff):
        raise HTTPException(400, "target_timestamp must be a full 'YYYY-MM-DD HH:MM:SS UTC' boundary.")
    with get_db() as db:
        db.query(LedgerBlock).filter(LedgerBlock.timestamp > cutoff).delete()
        db.query(VerificationLog).filter(VerificationLog.timestamp > cutoff).delete()
        db.commit()
        return {"status": "SUCCESS"}

# ==============================================================================
# [ COLUMN 8: DASHBOARDS & TELEMETRY ]
# ==============================================================================

def scoped_queries(db, admin: str, privileged: bool, limit: int | None = None,
                   offset: int = 0):
    """Resolve how much of the signed world a caller may see: normal signers only
    their own signer rows + blocks; super admins get the full network. Media
    blobs are deferred (never hydrated) — the ledger/network UIs don't need them
    and pulling every multi-MB blob on page load would stall the app.

    Blocks are newest-first and optionally paged (limit/offset) so callers that
    only render a handful of rows (e.g. the analytics "recent" strip) never pay
    for the whole table. limit=None preserves the legacy full pull."""
    _light = [defer(LedgerBlock.notice_media_data), defer(LedgerBlock.notice_content)]
    signers = db.query(SignerIdentity).all() if privileged else db.query(SignerIdentity).filter_by(email=admin).all()
    q = db.query(LedgerBlock).options(*_light)
    if not privileged:
        q = q.filter_by(signer_email=admin)
    q = q.order_by(LedgerBlock.id.desc())
    if offset:
        q = q.offset(offset)
    if limit is not None:
        q = q.limit(limit)
    return signers, q.all()

@app.get("/api/ledger")
@limiter.limit("120/minute")
def get_ledger(request: Request, admin: str = Depends(get_current_admin),
              limit: int | None = None, offset: int = 0):
    privileged = is_super_admin(admin)
    # Bounded pulls for callers that render a handful of rows (analytics page
    # asks for 7). Clamped so a hostile limit cannot become a full-table dump
    # by another name; None keeps the legacy full pull for the Authority desk.
    if limit is not None:
        limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset or 0))
    with get_db() as db:
        signers, block_rows = scoped_queries(db, admin, privileged, limit=limit, offset=offset)

        signers_out = {}
        for s in signers:
            signer_data = {
                "email": s.email, "name": s.name,
                "designation": s.designation or "", "institution": s.institution or "",
                "is_revoked": s.is_revoked, "has_pin": bool(s.revoke_pin),
            }
            # Key Issuance Ledger requirement: exact registration dates are a
            # super-admin-only audit affordance.
            if privileged:
                signer_data["registered_at"] = s.registered_at
                signer_data["revoked_at"] = s.revoked_at
            signers_out[s.email] = signer_data

        blocks_out = []
        for b in block_rows:
            parts = b.sig_hex.split(":")
            crypto_mode = parts[0] if len(parts) > 1 else "standard"
            blocks_out.append({
                "id": b.id, "signer_email": b.signer_email, "signer_name": b.signer_name,
                "signer_institution": b.signer_institution, "signer_designation": b.signer_designation,
                "filename": b.filename, "file_hash": b.file_hash, "sig_hex": b.sig_hex,
                "timestamp": b.timestamp, "ipfs_cid": b.ipfs_cid, "tx_hash": b.tx_hash,
                "merkle_root": b.merkle_root, "is_revoked": b.is_revoked,
                "crypto_mode": crypto_mode, "is_compromised": crypto_mode == "standard",
            })

        # `total` always means "rows matching your scope", not "rows on this
        # page": with a limit, count the scope (one indexed COUNT); without,
        # it is len(). Must run inside the session (above), not after close.
        if limit is None:
            total = len(blocks_out)
        else:
            _cq = db.query(func.count(LedgerBlock.id))
            if not privileged:
                _cq = _cq.filter_by(signer_email=admin)
            total = int(_cq.scalar() or 0)

    return {"signers": signers_out, "blocks": blocks_out, "total": total, "is_super_admin": privileged}

@app.get("/api/analytics")
@limiter.limit("120/minute")
def get_analytics(request: Request):
    # Aggregate-only, auth-free counters (identical to /api/stats in spirit) so
    # the analytics page works for visitors without a sign-in. No PII, no raw
    # records — just verdict tallies, latency stats and detector-provider counts.
    payload, _hit = _cached_section("analytics", _compute_analytics)
    return payload


@app.get("/api/analytics/summary")
@limiter.limit("120/minute")
def get_analytics_summary(request: Request):
    """One round trip for the whole dashboard: verdict tallies + latency +
    detector-provider counts + AI quota. The analytics page calls this once
    (prefetched at site load, refreshed live) instead of three serial requests,
    so a cold serverless instance is paid at most once per visit."""
    analytics, a_hit = _cached_section("analytics", _compute_analytics)
    usage, u_hit = _cached_section("usage", _compute_usage)
    return {"analytics": analytics, "usage": usage, "cached": bool(a_hit and u_hit)}


# ---------------------------------------------------------------------------
# Analytics cache: /api/analytics + /api/detection/usage are pure aggregates
# over the whole verification log, so recomputing them on every page view is
# waste. Cache each for ANALYTICS_CACHE_TTL seconds (default 20) and invalidate
# the moment a new verification lands. Per-process memory only (serverless
# instances each keep their own); correctness never depends on it because TTL
# expiry always recomputes from SQL.
# ---------------------------------------------------------------------------
_ANALYTICS_TTL = float(os.getenv("ANALYTICS_CACHE_TTL", "20") or 20)
_analytics_cache: dict = {"analytics": (0.0, None), "usage": (0.0, None)}


def _invalidate_analytics() -> None:
    _analytics_cache["analytics"] = (0.0, None)
    _analytics_cache["usage"] = (0.0, None)


def _cached_section(key: str, compute):
    at, payload = _analytics_cache.get(key, (0.0, None))
    if payload is not None and (time.monotonic() - at) < _ANALYTICS_TTL:
        return payload, True
    with get_db() as db:
        payload = compute(db)
    _analytics_cache[key] = (time.monotonic(), payload)
    return payload, False


def _compute_analytics(db) -> dict:
    """Aggregations run in SQL so the full VerificationLog table is never pulled
    into Python (the ledger grows unboundedly over time)."""
    stats = {"AUTHENTIC": 0, "PROVEN_FAKE": 0, "REVOKED": 0, "UNSIGNED": 0}
    # db.query() works on both SQLite and Postgres — no dialect branch needed.
    for status, count in db.query(VerificationLog.status, func.count(VerificationLog.id)) \
            .group_by(VerificationLog.status).all():
        stats[status] = int(count)

    lat_samples = db.query(func.count(VerificationLog.detection_ms),
                           func.avg(VerificationLog.detection_ms),
                           func.min(VerificationLog.detection_ms),
                           func.max(VerificationLog.detection_ms)) \
        .filter(VerificationLog.detection_ms.isnot(None)).one()
    samples = int(lat_samples[0] or 0)
    latency = None
    if samples:
        latency = {
            "avg_ms": int(round(lat_samples[1] or 0)),
            "min_ms": int(lat_samples[2] or 0),
            "max_ms": int(lat_samples[3] or 0),
            "samples": samples,
        }

    providers = {}
    for provider, count in db.query(VerificationLog.detection_provider,
                                    func.count(VerificationLog.id)) \
            .filter(VerificationLog.detection_provider.isnot(None)) \
            .group_by(VerificationLog.detection_provider).all():
        providers[provider] = int(count)
    return {"stats": stats, "latency": latency, "providers": providers}


# ---------------------------------------------------------------------------
# Sightengine quota tracking (server-side so the key and vendor internals are
# never exposed to the browser). We count the `operations` each check consumes
# into a persistent singleton row and expose only the derived "remaining" fields.
# ---------------------------------------------------------------------------
_SIGHTENGINE_DAILY_LIMIT = 500   # free tier: operations/day
_SIGHTENGINE_MONTHLY_LIMIT = 2000  # free tier: operations/month


def record_sightengine_usage(ops: int):
    if not ops:
        return
    now = datetime.now(timezone.utc)
    day = now.strftime("%Y-%m-%d")
    month = now.strftime("%Y-%m")
    try:
        with get_db() as db:
            stamp = now_utc()
            # Atomic increments â€” a plain read-modify-write could silently lose
            # operations under concurrent verifies (serverless = many workers).
            # Day/month rollover is a guarded UPDATE: reset the counter only if
            # the stored period is stale, THEN add ops, so resets and counts
            # cannot interleave into a lost update.
            db.execute(
                sa_update(SightengineUsage)
                .where(SightengineUsage.row_key == "global", SightengineUsage.day_date != day)
                .values(ops_today=0, day_date=day, updated_at=stamp)
            )
            db.execute(
                sa_update(SightengineUsage)
                .where(SightengineUsage.row_key == "global", SightengineUsage.month != month)
                .values(ops_month=0, month=month, updated_at=stamp)
            )
            res = db.execute(
                sa_update(SightengineUsage)
                .where(SightengineUsage.row_key == "global")
                .values(ops_today=SightengineUsage.ops_today + ops,
                        ops_month=SightengineUsage.ops_month + ops,
                        updated_at=stamp)
            )
            if res.rowcount == 0:
                db.add(SightengineUsage(row_key="global", ops_today=ops, ops_month=ops,
                                        day_date=day, month=month, updated_at=stamp))
            db.commit()
            # Quota numbers feed the analytics dashboard — drop its cache too.
            _invalidate_analytics()
    except Exception:
        # Quota bookkeeping must never break a verify â€” fail open.
        pass


@app.get("/api/detection/usage")
@limiter.limit("60/minute")
def detection_usage(request: Request):
    """Show how much Sightengine budget the app has used (day + month) and how
    much is left under the free-tier caps. No key / vendor internals exposed."""
    payload, _hit = _cached_section("usage", _compute_usage)
    return payload


def _compute_usage(db) -> dict:
    day = month = ops_today = ops_month = 0
    try:
        row = db.query(SightengineUsage).filter_by(row_key="global").first()
        if row:
            ops_today, ops_month = row.ops_today or 0, row.ops_month or 0
            day, month = row.day_date or "", row.month or ""
    except Exception:
        pass
    return {
        "provider": "sightengine",
        "model": os.getenv("AI_DETECTOR_MODELS", "genai"),
        "period_day": day,
        "period_month": month,
        "ops_used_today": ops_today,
        "ops_used_month": ops_month,
        "limit_today": _SIGHTENGINE_DAILY_LIMIT,
        "limit_month": _SIGHTENGINE_MONTHLY_LIMIT,
        "remaining_today": max(_SIGHTENGINE_DAILY_LIMIT - ops_today, 0),
        "remaining_month": max(_SIGHTENGINE_MONTHLY_LIMIT - ops_month, 0),
    }

@app.get("/api/network")
@limiter.limit("60/minute")
def get_network_graph(request: Request, admin: str = Depends(get_current_admin)):
    privileged = is_super_admin(admin)
    with get_db() as db:
        signers, block_rows = scoped_queries(db, admin, privileged)
        nodes = [
            {"id": s.email, "label": s.name + (f" ({s.designation})" if s.designation else ""),
             "group": "authority", "is_revoked": s.is_revoked}
            for s in signers
        ]
        edges = []
        for b in block_rows:
            crypto_mode = b.sig_hex.split(":")[0] if ":" in b.sig_hex else "standard"
            # Same compromised definition as /api/ledger: anything not signed in
            # the current hybrid mode is pre-hybrid ("standard") and flagged.
            is_compromised = crypto_mode == "standard"
            nodes.append({"id": b.file_hash, "label": b.filename, "group": "file",
                          "is_revoked": b.is_revoked, "crypto_mode": crypto_mode,
                          "is_compromised": is_compromised})
            edges.append({"from": b.signer_email, "to": b.file_hash})
        return {"nodes": nodes, "edges": edges}

@app.get("/api/stats")
@limiter.limit("120/minute")
def public_stats(request: Request):
    # Aggregate-only, auth-free counters (no PII) so the landing hero can show live network health.
    with get_db() as db:
        return {
            "signed_docs": db.query(LedgerBlock).count(),
            "trusted_issuers": db.query(SignerIdentity).count(),
        }

# ==============================================================================
# [ SCREENING DESK â€” MHA SIH26188: AI-Based Fake Identity & Document Screening ]
#
# Upload -> Extract -> Analyze -> Verify -> Assess Risk, with an immutable
# audit trail (ScreeningReport) and a hash-only watchlist. Screening is a desk
# operation: only signed-in officers can submit documents, every run is
# attributed to the screener, and adjudications are reserved for a supervisory
# officer (human-in-the-loop over the AI verdict).
# ==============================================================================

def _safe_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None

def _screen_row(r):
    """DB ScreeningReport row -> safe public-shaped dict (fields stay masked)."""
    return {
        "id": r.id,
        "filename": r.filename,
        "doc_type": r.doc_type or "other",
        "checkpoint": r.checkpoint or "",
        "verdict": r.verdict,
        "risk_score": r.risk_score,
        "confidence": r.confidence,
        "ledger_status": r.ledger_status,
        "screener": r.screener,
        "created_at": r.created_at,
        "adjudication": r.adjudication,
        "adjudicator": r.adjudicator,
        "adjudication_note": r.adjudication_note,
        "adjudicated_at": r.adjudicated_at,
        "masked_fields": _safe_json(r.extracted_fields),
    }

_SYNC_SCREENED_EXTS = ("pdf", "jpg", "jpeg", "png", "webp", "bmp")

@app.post("/api/screen")
@limiter.limit("60/minute")
async def screen_document(
    request: Request,
    file: UploadFile = Form(...),
    doc_type: str = Form("other"),
    checkpoint: str = Form(""),
    declared: str = Form(""),          # optional JSON map of officer-typed fields
    live_frame: UploadFile = Form(None),  # optional M4 webcam capture (image)
    admin: str = Depends(get_current_admin),
):
    data = await file.read()
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Document too large (8 MB cap).")
    ext = (file.filename or "").lower().rsplit(".", 1)[-1] if "." in (file.filename or "") else ""
    if ext not in _SYNC_SCREENED_EXTS:
        raise HTTPException(status_code=415, detail="Unsupported type — send a PDF or a jpg/png/webp/bmp image.")
    declared_map = {}
    if declared.strip():
        try:
            declared_map = json.loads(declared)
            if not isinstance(declared_map, dict):
                declared_map = {}
        except Exception:
            declared_map = {}
    live_bytes = await live_frame.read() if live_frame is not None else None
    if live_bytes and len(live_bytes) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Live frame too large (8 MB cap).")
    with get_db() as db:
        # The desk is open to any approved line officer â€" adjudication and the
        # watchlist stay supervisory â€" but a revoked or role-pending session
        # must not upload documents into the audit trail.
        if not is_super_admin(admin):
            identity = db.query(SignerIdentity).filter_by(email=admin).first()
            if not identity or identity.is_revoked:
                raise HTTPException(403, "ACCESS DENIED.")
            if not (identity.institution or "").strip() or not (identity.designation or "").strip():
                raise HTTPException(403, "Role pending: a super admin must approve your post & institution before screening.")
        report = run_screening(
            db, data, file.filename or "upload",
            (doc_type or "other").strip(), (checkpoint or "").strip(),
            declared_map, screener=admin, live_frame=live_bytes,
        )
        return report

@app.get("/api/screen/queue")
@limiter.limit("120/minute")
def screening_queue(request: Request, admin: str = Depends(get_current_admin)):
    # Supervisory officers see the whole desk; line officers see their own runs.
    # The scope filter lives in SQL BEFORE the LIMIT: filtering the latest 80
    # global rows in Python silently hid a line officer's own older runs.
    with get_db() as db:
        _q = db.query(ScreeningReport).order_by(ScreeningReport.created_at.desc())
        if not is_super_admin(admin):
            _q = _q.filter_by(screener=admin)
        rows = _q.limit(80).all()
        scoped = rows
        pending = [r for r in scoped if r.adjudication is None and r.verdict != "CLEAR"]
        return {
            "pending": [_screen_row(r) for r in pending],
            "recent": [_screen_row(r) for r in scoped],
        }

@app.get("/api/screen/reports/{report_id}")
@limiter.limit("120/minute")
def screening_report_detail(report_id: str, request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        r = db.query(ScreeningReport).filter_by(id=report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Screening report not found.")
        if not is_super_admin(admin) and r.screener != admin:
            raise HTTPException(status_code=403, detail="Not your screening record.")
        row = _screen_row(r)
        row["signals"] = _safe_json(r.signals) or []
        row["ai_detection"] = _safe_json(r.ai_detection)
        row["file_hash"] = r.file_hash
        return row

@app.post("/api/screen/reports/{report_id}/adjudicate")
@limiter.limit("60/minute")
def screen_adjudicate(
    report_id: str,
    request: Request,
    decision: str = Form(...),
    note: str = Form(""),
    admin: str = Depends(get_current_admin),
):
    if not is_super_admin(admin):
        raise HTTPException(status_code=403, detail="Only a supervisory officer can adjudicate screenings.")
    decision = decision.upper()
    if decision not in ("CLEARED", "CONFIRMED_FRAUD", "INCONCLUSIVE"):
        raise HTTPException(status_code=400, detail="Decision must be CLEARED, CONFIRMED_FRAUD or INCONCLUSIVE.")
    with get_db() as db:
        r = db.query(ScreeningReport).filter_by(id=report_id).first()
        if not r:
            raise HTTPException(status_code=404, detail="Screening report not found.")
        r.adjudication = decision
        r.adjudicator = admin
        r.adjudication_note = note.strip()
        r.adjudicated_at = now_utc()
        db.commit()
        return {"ok": True, "id": report_id, "adjudication": decision}

@app.get("/api/screen/watchlist")
@limiter.limit("120/minute")
def screening_watchlist(request: Request, admin: str = Depends(get_current_admin)):
    if not is_super_admin(admin):
        raise HTTPException(status_code=403, detail="Watchlist access requires a supervisory officer.")
    with get_db() as db:
        rows = (db.query(WatchlistEntry)
                .order_by(WatchlistEntry.created_at.desc())
                .limit(300).all())
        return {"entries": [
            {"id": e.id, "category": e.category, "mask": e.mask,
             "reason": e.reason, "added_by": e.added_by, "created_at": e.created_at}
            for e in rows
        ]}


@app.get("/api/screen/shift-export")
@limiter.limit("30/minute")
def screening_shift_export(
    request: Request,
    from_date: str = "",
    to_date: str = "",
    checkpoint: str = "",
    admin: str = Depends(get_current_admin),
):
    """Export the shift screening log as a signed CSV (chain-of-custody receipt)."""
    import csv
    import io
    from datetime import datetime, timezone

    if not is_super_admin(admin):
        raise HTTPException(status_code=403, detail="Shift export requires supervisory access.")

    with get_db() as db:
        q = db.query(ScreeningReport).order_by(ScreeningReport.created_at.asc())
        if from_date.strip():
            q = q.filter(ScreeningReport.created_at >= from_date.strip())
        if to_date.strip():
            q = q.filter(ScreeningReport.created_at <= to_date.strip() + " 23:59:59")
        if checkpoint.strip():
            q = q.filter(ScreeningReport.checkpoint == checkpoint.strip())
        rows = q.limit(5000).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["# Veri_source Shift Log — SIH26188 MHA Screening Desk"])
    writer.writerow([f"# Exported by: {admin}", f"# At: {datetime.now(timezone.utc).isoformat()}"])
    writer.writerow([
        "id", "doc_type", "checkpoint", "verdict", "risk_score",
        "confidence", "ledger_status", "screener", "adjudication",
        "adjudicator", "created_at", "masked_fields",
    ])
    for r in rows:
        writer.writerow([
            r.id, r.doc_type or "other", r.checkpoint or "",
            r.verdict, r.risk_score, r.confidence, r.ledger_status,
            r.screener or "", r.adjudication or "", r.adjudicator or "",
            r.created_at, r.extracted_fields or "{}",
        ])

    csv_body = buf.getvalue()
    import hashlib as _hl
    digest = _hl.sha256(csv_body.encode("utf-8")).hexdigest()
    signed_csv = csv_body + f"\n# SHA-256: {digest}\n"

    from fastapi.responses import Response as _Resp
    fname = f"shift_log_{(from_date or 'all').replace('-','')}_to_{(to_date or 'now').replace('-','')}.csv"
    return _Resp(
        content=signed_csv.encode("utf-8"),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/screen/syndicate-alerts")
@limiter.limit("60/minute")
def screening_syndicate_alerts(
    request: Request,
    checkpoint: str = "",
    admin: str = Depends(get_current_admin),
):
    """Retrieve real-time cross-border syndicate, recidivism, and sector burst alerts."""
    from syndicate import analyze_syndicate_patterns
    target_cp = checkpoint.strip()
    with get_db() as db:
        # Pull global recent history so cross-checkpoint syndicates are detectable
        rows = db.query(ScreeningReport).order_by(ScreeningReport.created_at.desc()).limit(200).all()

    history = []
    for r in rows:
        ef = {}
        try:
            ef = json.loads(r.extracted_fields or "{}")
        except Exception:
            pass
        history.append({
            "file_hash": r.file_hash,
            "checkpoint": r.checkpoint,
            "doc_number": ef.get("passport") or ef.get("pan") or ef.get("driving_licence") or ef.get("voter_id"),
            "name": ef.get("mrz_name") or ef.get("holder_name") or ef.get("name"),
            "dob": ef.get("dob"),
            "verdict": r.verdict,
            "created_at": r.created_at,
        })

    # If a checkpoint filter is requested, analyze items from that checkpoint against full history
    eval_pool = [h for h in history if not target_cp or (h.get("checkpoint") or "").strip() == target_cp]

    all_alerts = []
    for item in eval_pool[:30]:
        res = analyze_syndicate_patterns(item, history)
        for a in res.get("alerts", []):
            if a not in all_alerts:
                all_alerts.append(a)

    return {
        "checkpoint_filter": target_cp or "ALL",
        "total_screened_sample": len(history),
        "alerts": all_alerts,
        "active_alerts_count": len(all_alerts),
    }


@app.get("/api/screen/dossier/{report_id}")
@limiter.limit("60/minute")
def screening_evidentiary_dossier(
    request: Request,
    report_id: str,
    admin: str = Depends(get_current_admin),
):
    """Generate a court-admissible, tamper-evident forensic dossier (printable HTML/PDF)."""
    import html
    with get_db() as db:
        report = db.query(ScreeningReport).filter_by(id=report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Screening report not found.")

    ef = {}
    try:
        ef = json.loads(report.extracted_fields or "{}")
    except Exception:
        pass

    sig_list = []
    try:
        sig_list = json.loads(report.signals or "[]")
    except Exception:
        pass

    mod_dict = {}
    try:
        mod_dict = json.loads(report.modules or "{}")
    except Exception:
        pass

    dossier_payload = f"{report.id}:{report.file_hash}:{report.verdict}:{report.risk_score}:{report.created_at}:{admin}"
    dossier_seal = hmac.new(MASTER_VAULT_KEY, dossier_payload.encode("utf-8"), hashlib.sha256).hexdigest()

    badge_color = "#10b981" if report.verdict == "CLEAR" else ("#f59e0b" if report.verdict == "REVIEW" else "#ef4444")
    fields_html = "".join(f"<div><strong>{html.escape(str(k)).upper()}:</strong> {html.escape(str(v))}</div>" for k, v in ef.items() if v)
    signals_html = "".join(f"<li>{html.escape(str(sig))}</li>" for sig in sig_list) if sig_list else "<li>Clean screening pass — no anomalous signals.</li>"

    safe_report_id = html.escape(str(report.id))
    safe_cp = html.escape(str(report.checkpoint or 'Official Border Checkpost'))
    safe_officer = html.escape(str(admin))
    safe_verdict = html.escape(str(report.verdict))
    safe_created_at = html.escape(str(report.created_at))
    safe_doc_type = html.escape(str(report.doc_type or 'Identity Document'))
    safe_file_hash = html.escape(str(report.file_hash))
    safe_ledger_status = html.escape(str(report.ledger_status or 'UNREGISTERED'))

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Evidentiary Forensic Dossier — {safe_report_id}</title>
<style>
  body {{ font-family: 'Courier New', Courier, monospace; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
  .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; border: 2px solid #334155; border-radius: 8px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
  .header {{ border-bottom: 2px solid #475569; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }}
  .header h1 {{ margin: 0; font-size: 20px; color: #38bdf8; text-transform: uppercase; letter-spacing: 1px; }}
  .header p {{ margin: 4px 0 0 0; font-size: 12px; color: #94a3b8; }}
  .badge {{ display: inline-block; padding: 6px 14px; font-weight: bold; border-radius: 4px; color: #fff; background: {badge_color}; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; font-size: 13px; }}
  .section {{ margin-bottom: 24px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 16px; }}
  .section h2 {{ font-size: 14px; color: #93c5fd; margin-top: 0; text-transform: uppercase; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
  ul {{ margin: 0; padding-left: 20px; }}
  li {{ margin-bottom: 6px; font-size: 13px; }}
  .seal-box {{ background: #020617; border: 1px dashed #64748b; padding: 16px; border-radius: 6px; font-size: 11px; word-break: break-all; }}
  @media print {{
    body {{ background: #fff; color: #000; padding: 0; }}
    .container {{ border: none; box-shadow: none; padding: 0; background: #fff; color: #000; }}
    .section {{ background: #f8fafc; border: 1px solid #cbd5e1; color: #000; }}
    .seal-box {{ background: #f1f5f9; border: 1px solid #cbd5e1; color: #000; }}
    .header h1 {{ color: #000; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>Ministry of Home Affairs · SSB Border Screening Desk</h1>
      <p>Forensic Chain-of-Custody Dossier · Statutory Inspection Record (SIH26188)</p>
      <p>Checkpoint: <strong>{safe_cp}</strong> | Officer: <strong>{safe_officer}</strong></p>
    </div>
    <div>
      <span class="badge">{safe_verdict} (Risk {report.risk_score}/100)</span>
    </div>
  </div>

  <div class="grid">
    <div><strong>Report ID:</strong> {safe_report_id}</div>
    <div><strong>Created At:</strong> {safe_created_at}</div>
    <div><strong>Document Type:</strong> {safe_doc_type}</div>
    <div><strong>Confidence Score:</strong> {int(report.confidence * 100)}%</div>
    <div><strong>File Fingerprint (SHA-256):</strong> <span style="font-size:11px;">{safe_file_hash}</span></div>
    <div><strong>Ledger Provenance Status:</strong> {safe_ledger_status}</div>
  </div>

  <div class="section">
    <h2>Masked Identifier Fields (Privacy-Preserving)</h2>
    <div class="grid">
      {fields_html}
    </div>
  </div>

  <div class="section">
    <h2>Four-Module Inspection Matrix</h2>
    <ul>
      <li><strong>Module 1 (OCR Extraction):</strong> {'Extracted successfully' if mod_dict.get('extraction') else 'Executed'} (Medium: {mod_dict.get('extraction', {}).get('medium', 'N/A')})</li>
      <li><strong>Module 2 (Document Validation):</strong> Status {mod_dict.get('validation', {}).get('verdict', 'N/A')}</li>
      <li><strong>Module 3 (AI Tampering & Forensics):</strong> Status {mod_dict.get('tampering', {}).get('verdict', 'N/A')}</li>
      <li><strong>Module 4 (Biometric Face Verification):</strong> Status {mod_dict.get('face', {}).get('verdict', 'N/A')}</li>
    </ul>
  </div>

  <div class="section">
    <h2>Explainable Forensic Signals & Reasons</h2>
    <ul>
      {signals_html}
    </ul>
  </div>

  <div class="seal-box">
    <strong>CRYPTOGRAPHIC CUSTODY SEAL (HMAC-SHA256):</strong><br/>
    {dossier_seal}<br/><br/>
    <em>This document is an electronically generated statutory evidence record pursuant to the Indian Evidence Act & Bharatiya Sakshya Adhiniyam standards for digital evidence. Tamper-proof cryptographic provenance anchored to the border inspection authority key.</em>
  </div>
</div>
<script>
  if (window.location.search.includes("print=true")) {{
    window.print();
  }}
</script>
</body>
</html>"""

    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content)


@app.post("/api/screen/watchlist/add")
@limiter.limit("60/minute")
def screening_watchlist_add(
    request: Request,
    category: str = Form(...),
    value: str = Form(...),
    reason: str = Form(""),
    admin: str = Depends(get_current_admin),
):
    from screening import norm, mask, sha256
    if not is_super_admin(admin):
        raise HTTPException(status_code=403, detail="Watchlist access requires a supervisory officer.")
    if not value.strip():
        raise HTTPException(status_code=400, detail="An identifier value is required.")
    v = norm(value)
    with get_db() as db:
        existing = db.query(WatchlistEntry).filter_by(identifier_hash=sha256(v)).first()
        if existing:
            return {"ok": True, "already": True, "id": existing.id, "mask": existing.mask}
        entry = WatchlistEntry(
            identifier_hash=sha256(v),
            category=(category or "").strip() or None,
            mask=mask(v),
            reason=(reason or "").strip() or None,
            added_by=admin,
            created_at=now_utc(),
        )
        db.add(entry)
        try:
            db.commit()
        except IntegrityError:
            # Lost the concurrent-add race (or a legacy duplicate): the unique
            # index now guards this, so return the surviving row as "already".
            db.rollback()
            existing = db.query(WatchlistEntry).filter_by(identifier_hash=sha256(v)).first()
            return {"ok": True, "already": True,
                    "id": existing.id if existing else None,
                    "mask": existing.mask if existing else mask(v)}
        return {"ok": True, "id": entry.id, "mask": entry.mask}

@app.post("/api/screen/watchlist/remove")
@limiter.limit("60/minute")
def screening_watchlist_remove(
    request: Request,
    entry_id: int = Form(...),
    admin: str = Depends(get_current_admin),
):
    if not is_super_admin(admin):
        raise HTTPException(status_code=403, detail="Watchlist access requires a supervisory officer.")
    with get_db() as db:
        entry = db.query(WatchlistEntry).filter_by(id=entry_id).first()
        if not entry:
            raise HTTPException(status_code=404, detail="Watchlist entry not found.")
        db.delete(entry)
        db.commit()
        return {"ok": True}



# ============================================================================
# AI assistant — project-scoped Gemini chat with full codebase database ingestion
# ============================================================================
# NOTE: `codebase as codebase_index` is already imported near the top of this
# module (line ~562); do not re-import it here.

GEMINI_MODEL = (os.getenv("GEMINI_MODEL") or "gemini-3.5-flash-lite").strip()
GEMINI_KEY = (os.getenv("GEMINI_API_KEY") or os.getenv("GEMINI_KEY") or "").strip()

GEMINI_SYSTEM_PROMPT = (
    "You are 'nocap', the lead technical architect & AI code oracle for the nocap / Veri_source "
    "Cryptographic Provenance Ledger platform.\n\n"
    "VISIBILITY:\n"
    "You have been provided with the COMPLETE, ACTUAL SOURCE CODE DATABASE of the entire project "
    "repository in your context. Every backend route, cryptographic vault, database schema, "
    "verification algorithm, screening check, React component, CSS design token, test case, and "
    "technical study guide is loaded in full with 1-based line numbers.\n\n"
    "HOW TO ANSWER:\n"
    "- Deep Code Grounding: Read and search the complete CODE DATABASE to answer accurately about ANY part of the project.\n"
    "- Exact Citations: Always cite exact file paths and line numbers whenever referencing code (e.g. `app/main.py:1124-1175`, `app/screening.py:120`, `frontend/src/components/VerdictCard.tsx:42`).\n"
    "- End-to-End Traces: Explain how frontend, backend, cryptography, database schemas, and blockchain anchoring connect across the stack.\n"
    "- Algorithmic Rigor: When explaining algorithms (e.g. ICAO 9303 MRZ check digits, ECDSA secp256k1, AES-256-GCM vault, ELA forensic analysis, Merkle tree anchoring), detail the exact logic and quote the code lines.\n"
    "- Complete Code Blocks: Provide complete, un-truncated, syntax-highlighted code blocks in markdown when answering implementation questions.\n"
    "- Technical Scope: Answer thoroughly on all aspects of nocap/Veri_source. If asked anything completely unrelated to this project (e.g. recipes, celebrity trivia), politely decline in one sentence and offer to help with nocap instead."
)


def _chat_history_turns(message, history):
    turns = []
    if isinstance(history, list):
        for h in history[-10:]:
            if not isinstance(h, dict):
                continue
            role = h.get("role")
            text = (h.get("text") or h.get("content") or "").strip()
            if role not in ("user", "model", "assistant", "bot") or not text:
                continue
            gem_role = "model" if role in ("model", "assistant", "bot") else "user"
            text = text[:4000]
            if turns and turns[-1]["role"] == gem_role:
                turns[-1]["parts"][0]["text"] += "\n" + text
            else:
                turns.append({"role": gem_role, "parts": [{"text": text}]})
    turns.append({"role": "user", "parts": [{"text": message[:8000]}]})
    return turns


def _gemini_reply(message, history):
    api_key = (os.getenv("GEMINI_API_KEY") or os.getenv("GEMINI_KEY") or GEMINI_KEY).strip()
    primary_model = (os.getenv("GEMINI_MODEL") or GEMINI_MODEL or "gemini-3.5-flash-lite").strip()
    if not api_key:
        return {"ok": False, "reason": "unconfigured"}

    prompt = GEMINI_SYSTEM_PROMPT
    try:
        code_ctx = codebase_index.codebase_context(message)
    except Exception as e:
        print(f"[_gemini_reply] Warning: codebase_context error: {e}")
        code_ctx = ""

    if code_ctx:
        prompt = GEMINI_SYSTEM_PROMPT + "\n\n" + code_ctx

    body = {
        "systemInstruction": {"parts": [{"text": prompt}]},
        "contents": _chat_history_turns(message, history),
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096, "candidateCount": 1},
    }
    params = {"key": api_key}
    headers = {"Content-Type": "application/json"}

    candidate_models = [primary_model]
    for m in ("gemini-3.5-flash-lite", "gemini-3.6-flash", "gemini-flash-latest", "gemini-2.5-flash", "gemini-3.1-flash-lite"):
        if m not in candidate_models:
            candidate_models.append(m)

    last_resp = None
    for model in candidate_models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        try:
            import requests
            resp = requests.post(url, json=body, headers=headers, params=params, timeout=(15, 90))
        except Exception as e: # Catch all since requests exception might not be imported

            print(f"[_gemini_reply] RequestException for model {model}: {e}")
            continue
        last_resp = resp
        if resp.status_code == 200:
            data = resp.json()
            parts = (data.get("candidates") or [{}])[0].get("content", {}).get("parts") or []
            text = "".join(p.get("text") or "" for p in parts).strip()
            if text:
                return {"ok": True, "answer": text}
            block = (data.get("promptFeedback") or {}).get("blockReason")
            return {"ok": False, "reason": "blocked", "detail": block}
        if resp.status_code in (400, 401, 403):
            print(f"[_gemini_reply] Auth/Key error {resp.status_code}: {resp.text[:200]}")
            return {"ok": False, "reason": "key_invalid"}
        # If rate-limited (429), not found (404), or server error (5xx), try the next candidate model
        print(f"[_gemini_reply] Model {model} returned {resp.status_code}, trying fallback...")
        continue

    if last_resp is not None:
        if last_resp.status_code == 429:
            return {"ok": False, "reason": "rate_limited"}
        return {"ok": False, "reason": "error", "detail": last_resp.text[:120]}
    return {"ok": False, "reason": "error"}


@app.post("/api/chat")
@limiter.limit("30/minute")
async def ai_chat(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "Send a JSON body with a 'message' field.")
    message = str(payload.get("message") or "").strip()
    if not message:
        raise HTTPException(400, "'message' is required.")
    history = payload.get("history") or []
    result = await run_in_threadpool(_gemini_reply, message, history)
    if result.get("ok"):
        return {"ok": True, "answer": result["answer"]}
    reason = result.get("reason")
    if reason == "unconfigured":
        message_note = ("The AI assistant is not configured yet — add a GEMINI_API_KEY env "
                        "var on the server. The offline guide still works.")
    elif reason == "key_invalid":
        message_note = ("The AI assistant's key was rejected — check the GEMINI_API_KEY env "
                        "var. Using the offline guide for now.")
    elif reason == "rate_limited":
        message_note = "The AI is busy right now — try again in a minute."
    else:
        message_note = "The AI assistant hit an error — please try again."
    return {"ok": False, "reason": reason, "message": message_note}

