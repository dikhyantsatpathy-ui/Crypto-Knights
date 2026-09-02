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

import os
import time

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
_AUTO = True


def _select_backend():
    provider = (os.getenv("AI_DETECTOR_PROVIDER") or "").strip().lower()
    if provider == "sightengine":
        return "sightengine" if os.getenv("AI_DETECTOR_KEY") else "heuristic"
    if provider == "self-hosted":
        return "self-hosted"
    return "heuristic"


BACKEND = _select_backend()

# Resolve the concrete detector functions lazily so importing this module never
# pulls heavyweight deps (onnxruntime / requests) unless they are needed.
_detector_ai = None
_detector_score = None


def _load():
    global _detector_ai, _detector_score
    if _detector_ai is not None:
        return
    if BACKEND == "sightengine":
        from .provider_sightengine import sightengine_detect, sightengine_score
        _detector_ai, _detector_score = sightengine_detect, sightengine_score
    elif BACKEND == "self-hosted":
        from .self_hosted import onnx_detect, onnx_score
        _detector_ai, _detector_score = onnx_detect, onnx_score
    else:
        from .heuristic import heuristic_detect, heuristic_score
        _detector_ai, _detector_score = heuristic_detect, heuristic_score


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
    (e.g. a scanned notice) we skip the AI-art detectors entirely — they are
    trained for photos and would misfire and waste the cloud budget. Instead we
    return a document verdict that points trust to the signature/provenance."""
    if not image_bytes:
        return _empty("No image data was provided, so it could not be analysed for AI generation.")
    start = time.perf_counter()
    try:
        from .document_aware import looks_like_scanned_document, document_verdict
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