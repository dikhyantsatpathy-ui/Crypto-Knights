"""
Sightengine AI-detection backend (cloud, trained model).

Recommended real-model backend for the judge-facing demo: a hosted, pre-trained
neural classifier returns a genuine confidence score (`type.ai_generated`), and
names which generator(s) built the image. Fast (<500ms typical), never needs a
GPU of our own, but DOES send the image bytes to a third party — only enable it
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

import os
import time

import requests

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