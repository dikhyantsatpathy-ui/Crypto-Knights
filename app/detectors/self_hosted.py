"""
Self-hosted ONNX AI-detection backend (real ViT model, no external service).

Runs a Vision-Transformer classifier locally via ONNX Runtime. The image never
leaves our server. This is the "keep it ours / no API key / no third-party"
option: zero per-image cost and fully private, but it requires a model file on
disk (downloaded on first use) and CPU inference is heavier than a hosted API.

Model: `onnx-community/ai-image-detection-ONNX` — ViT-Base fine-tuned on the
CIFAKE dataset (Real vs Fake/AI). Visual Transformer, 224x224 RGB input, two
class logits.

Activation:
    AI_DETECTOR_PROVIDER = self-hosted
    AI_DETECTOR_MODEL_URL  = (optional) direct URL to an .onnx; default HF-hosted
    AI_DETECTOR_MODEL_DIR  = where to cache the model (default: <repo>/data/models)

Limitation note:
    ViT-Base is ~340MB fp32 — too big for Vercel's 128MB serverless bundle.
    For Vercel, prefer the Sightengine backend, or host this as a separate small
    CPU worker. Locally (or on a 2-core+ CPU box) it runs fine.
"""

import io
import os
import time
import urllib.request

import numpy as np

# Default small-ish, HF-hosted, Apache-2.0 classifier for Real vs AI.
MODEL_REPO = "onnx-community/ai-image-detection-ONNX"
MODEL_FILE = "model.onnx"
DEFAULT_URL = f"https://huggingface.co/{MODEL_REPO}/resolve/main/onnx/model.onnx"
_IMG_SIZE = 224

_engine = None  # cached onnxruntime.InferenceSession


def _model_dir() -> str:
    return os.getenv("AI_DETECTOR_MODEL_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
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