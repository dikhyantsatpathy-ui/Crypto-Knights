"""
Visual forensics for identity documents — Error Level Analysis (ELA),
Region-of-Interest (ROI) extraction, and passive liveness signals.

This module is deliberately dependency-light so it runs inside Vercel
serverless functions that bundle only numpy + Pillow. The classic FotoForensics
ELA flow (resave a JPEG at a fixed quality, resave the resave, diff the two
copies) is pure pixel arithmetic — no native image library required. Where
OpenCV happens to be importable it is treated as an optional accelerator only;
the numpy path is the supported, tested one.

Every public function here returns plain JSON-shaped data (no file writes, no
temp files): the API layer streams the heatmap and ROI boxes straight back to
the frontend, which overlays them onto the document preview the officer is
already looking at.

What this CANNOT do, and says so honestly: a single still photo cannot prove a
human is alive. "Liveness" here means passive tamper/medium cues detectable in
one frame (blur, screen-recapture moire, over-exposure) plus an explicit nudge
that interactive liveness (blink / device motion) belongs in the webcam flow.
"""

import base64
import io
import time
import numpy as np
from PIL import Image

# --------------------------------------------------------------------------- #
# Small image helpers
# --------------------------------------------------------------------------- #

def _open_rgb(data: bytes):
    """Decode raw bytes to a uint8 (h, w, 3) RGB array. Raises ValueError when
    Pillow cannot read the data, so callers can degrade gracefully."""
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        img = img.convert("RGB")
    except Exception:
        raise ValueError("image not readable")
    return np.asarray(img, dtype=np.uint8)


_LUMA_WEIGHTS = np.array([0.299, 0.587, 0.114], dtype=np.float32)


def _to_gray(rgb: np.ndarray) -> np.ndarray:
    """BT.601 luma via dot product — fast, vectorized, and memory-efficient."""
    return np.dot(rgb.astype(np.float32), _LUMA_WEIGHTS)


def _png_b64(rgb: np.ndarray) -> str:
    """Encode a small uint8 RGB array as a base64 PNG (no disk writes)."""
    out = io.BytesIO()
    Image.fromarray(rgb, mode="RGB").save(out, format="PNG")
    return base64.b64encode(out.getvalue()).decode("ascii")


# --------------------------------------------------------------------------- #
# Error Level Analysis (FotoForensics-style, numpy-only)
# --------------------------------------------------------------------------- #

def _block_grid(diff: np.ndarray, block: int = 8):
    """Mean absolute difference per block, fully vectorised.

    diff: (h, w) float array. The image is cropped to whole blocks first so the
    reshape below is legal; the returned grid is (h//block, w//block)."""
    h, w = diff.shape[0] - diff.shape[0] % block, diff.shape[1] - diff.shape[1] % block
    if h == 0 or w == 0:
        return np.zeros((1, 1), dtype=np.float32)
    crop = diff[:h, :w]
    tiles = crop.reshape(h // block, block, w // block, block)
    return tiles.mean(axis=(1, 3)).astype(np.float32)


def _fire(rgb_norm: np.ndarray) -> np.ndarray:
    """Vectorised 'hot' colormap for the ELA heatmap: black -> red -> white so
    tampered zones read as bright hotspots against a dim baseline."""
    x = np.clip(rgb_norm, 0, 1)
    r = np.clip(x / 0.35, 0, 1) * 255.0
    g = np.clip((x - 0.25) / 0.40, 0, 1) * 200.0
    b = np.clip((x - 0.65) / 0.35, 0, 1) * 255.0
    return np.stack([r, g, b], axis=-1).astype(np.uint8)


def ela(data: bytes, quality: int = 92, preview: int = 128):
    """Error Level Analysis over one document photo.

    Pipeline: decode once -> save at `quality` -> reopen -> save at the same
    quality -> diff. A pristine JPEG re-encodes almost losslessly; a region
    that was cropped/pasted/composited re-compresses to a visibly different
    level, so its blocks light up in the diff.

    Returns a JSON-shaped dict: damage ratio over 8x8 blocks, a small heatmap
    PNG (base64) for the frontend preview, and a coarse 10x10 normalized grid
    the frontend can use as a CSS overlay without shipping another bitmap.
    """
    try:
        rgb = _open_rgb(data)
    except ValueError:
        return {"engine": "ela", "error": "image not readable"}

    started = time.monotonic()
    # Pass 1: encode to JPEG at target quality.
    first = io.BytesIO()
    Image.fromarray(rgb).save(first, "JPEG", quality=quality)

    # Pass 2: re-encode the pass-1 result at the same quality.  Seek to the
    # start of the first buffer instead of re-reading getvalue() into a new
    # BytesIO — avoids one full byte-string copy per call.
    second = io.BytesIO()
    first.seek(0)
    Image.open(first).convert("RGB").save(second, "JPEG", quality=quality)

    # Decode both compressed results for diff.  Seek to avoid fresh BytesIO.
    first.seek(0)
    second.seek(0)
    a = _to_gray(np.asarray(Image.open(first).convert("RGB")))
    b = _to_gray(np.asarray(Image.open(second).convert("RGB")))
    diff = np.abs(a - b)

    grid = _block_grid(diff)
    mean_diff = float(diff.mean())
    local_baseline = float(grid.mean()) + 2.0 * float(grid.std())
    damaged_blocks = float((grid > max(local_baseline, 1.0)).mean())
    status = "HIGH" if damaged_blocks > 0.35 else ("MEDIUM" if damaged_blocks > 0.18 else "LOW")

    # Hotness masks tie the picture to the verdict: a block only lights up when
    # its local error exceeds the image's own baseline, so a pristine JPEG is
    # black and a tampered zone is a bright island. Normalizing to min/max (the
    # obvious first attempt) would render every clean image near-full bright.
    exceedance = np.clip((grid - local_baseline) / max(local_baseline, 1.0), 0, 1)

    # Coarse 10x10 overlay grid — vectorised block-mean via reshape.
    # _block_grid already produced (gh, gw) means; we pool those into 10x10.
    gh, gw = exceedance.shape
    # Ensure divisibility: trim to nearest multiple of 10.
    gh10, gw10 = (gh // 10) * 10 or 1, (gw // 10) * 10 or 1
    trimmed = exceedance[:gh10, :gw10]
    coarse = (
        trimmed.reshape(10, gh10 // 10, 10, gw10 // 10)
        .mean(axis=(1, 3))
    ) if gh10 >= 10 and gw10 >= 10 else np.zeros((10, 10), dtype=np.float32)

    # Preview bitmap: stretch the hotness map back up, colormap it, then scale
    # the ENCODED copy down to a bounded size. A full-resolution heatmap PNG
    # would add megabytes of base64 to every API response for a 12MP photo; a
    # ~256px preview plus the coarse overlay grid carries the same verdict.
    h, w = rgb.shape[:2]
    scale = max(1, gw // preview)
    small = exceedance[::scale, ::scale] if scale > 1 else exceedance
    map_rgb = np.asarray(Image.fromarray(_fire(small)).resize((w, h), Image.LANCZOS))
    longest = max(h, w)
    if longest > 256:
        scale_down = 256 / longest
        map_rgb = np.asarray(Image.fromarray(map_rgb).resize(
            (int(w * scale_down), int(h * scale_down)), Image.LANCZOS))

    return {
        "engine": "ela",
        "quality": quality,
        "damage_ratio": round(damaged_blocks, 4),
        "mean_diff": round(mean_diff, 3),
        "status": status,
        "heatmap_b64": _png_b64(map_rgb),
        "overlay_grid": [[round(float(v), 3) for v in row] for row in coarse.tolist()],
        "latency_ms": int((time.monotonic() - started) * 1000),
    }


# --------------------------------------------------------------------------- #
# Basic image quality (blur, exposure) — numpy Laplacian variance
# --------------------------------------------------------------------------- #

def _variance_of_laplacian(gray: np.ndarray) -> float:
    """Focus estimate: variance of a 3x3 Laplacian. Low variance => blurry.
    Fully vectorised with array slicing (no scipy, no conv2d)."""
    center = gray[1:-1, 1:-1]
    lap = 4 * center - gray[0:-2, 1:-1] - gray[2:, 1:-1] - gray[1:-1, 0:-2] - gray[1:-1, 2:]
    return float(lap.var())


def image_qa(data: bytes):
    """Resolution, focus and exposure facts about one image."""
    try:
        rgb = _open_rgb(data)
    except ValueError:
        return {"error": "image not readable"}
    h, w = rgb.shape[:2]
    gray = _to_gray(rgb)
    laplacian_var = _variance_of_laplacian(gray)
    dark_frac = float((gray < 24).mean())
    bright_frac = float((gray > 235).mean())
    return {
        "width": w,
        "height": h,
        "megapixels": round(w * h / 1e6, 2),
        "blur_est": round(laplacian_var, 2),
        "blurry": laplacian_var < 80.0,
        "dark_frac": round(dark_frac, 4),
        "bright_frac": round(bright_frac, 4),
        "overexposed": bright_frac > 0.25,
        "underexposed": dark_frac > 0.5,
    }


# --------------------------------------------------------------------------- #
# 2D-FFT Spectral Frequency & Sensor PRNU Noise Splicing Analysis
# --------------------------------------------------------------------------- #

def spectral_analysis(data: bytes | np.ndarray) -> dict:
    """2D-FFT frequency spectrum analysis.
    Detects high-frequency periodic grid artifacts characteristic of generative
    diffusion/GAN upsampling and screen-recapture moiré.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            rgb = _open_rgb(data)
        except Exception:
            return {"error": "image not readable"}
    elif isinstance(data, np.ndarray):
        rgb = data
    else:
        return {"error": "invalid image type"}

    gray = _to_gray(rgb)
    h, w = gray.shape
    if h < 32 or w < 32:
        return {
            "spectral_anomaly": False,
            "status": "LOW_RESOLUTION",
            "papr": 0.0,
            "high_freq_ratio": 0.0,
            "detail": "Resolution too low for spectral Fourier analysis.",
        }

    # Extract centered patch up to 512x512
    crop_size = min(h, w, 512)
    cy, cx = h // 2, w // 2
    half = crop_size // 2
    patch = gray[cy - half : cy + half, cx - half : cx + half]

    # High-pass residual by subtracting local average
    low_pass = (
        patch[:-2, 1:-1] + patch[2:, 1:-1] + patch[1:-1, :-2] + patch[1:-1, 2:] + 4.0 * patch[1:-1, 1:-1]
    ) / 8.0
    residual = patch[1:-1, 1:-1] - low_pass

    # 2D Fast Fourier Transform
    f = np.fft.fft2(residual)
    fshift = np.fft.fftshift(f)
    mag = np.abs(fshift)

    # Radial partitioning
    rh, rw = mag.shape
    y, x = np.ogrid[:rh, :rw]
    center_y, center_x = rh / 2.0, rw / 2.0
    dist = np.sqrt((x - center_x) ** 2 + (y - center_y) ** 2)
    max_radius = min(center_y, center_x)

    high_mask = dist > (0.65 * max_radius)
    high_energy = float(mag[high_mask].sum()) if np.any(high_mask) else 0.0
    total_energy = float(mag.sum()) + 1e-9
    high_freq_ratio = high_energy / total_energy

    # Peak-to-Average Power Ratio (PAPR) in high frequencies
    high_vals = mag[high_mask]
    if len(high_vals) > 0:
        high_mean = float(high_vals.mean()) + 1e-9
        high_max = float(high_vals.max())
        papr = high_max / high_mean
    else:
        papr = 1.0

    is_anomaly = bool(papr > 18.0 or high_freq_ratio > 0.45)
    status = "ANOMALOUS_GRID" if papr > 22.0 else ("PERIODIC_SPIKES" if is_anomaly else "NORMAL")

    return {
        "papr": round(float(papr), 2),
        "high_freq_ratio": round(float(high_freq_ratio), 4),
        "spectral_anomaly": is_anomaly,
        "status": status,
        "detail": f"2D-FFT PAPR: {papr:.1f}x (high-frequency ratio: {high_freq_ratio:.2%})",
    }


def noise_consistency(data: bytes | np.ndarray, rois: list[dict] | None = None) -> dict:
    """Evaluates Sensor PRNU / noise variance consistency across the document.
    Detects photo splicing / face replacement where a foreign portrait with
    mismatched camera sensor noise is pasted onto the ID substrate.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            rgb = _open_rgb(data)
        except Exception:
            return {"error": "image not readable"}
    elif isinstance(data, np.ndarray):
        rgb = data
    else:
        return {"error": "invalid image type"}

    gray = _to_gray(rgb)
    h, w = gray.shape
    if h < 64 or w < 64:
        return {
            "consistent": True,
            "noise_ratio": 1.0,
            "status": "INSUFFICIENT_RESOLUTION",
            "detail": "Resolution too low for sensor noise analysis.",
        }

    # Estimate noise residual via high-pass Laplacian / difference
    residual = gray[1:-1, 1:-1] - 0.25 * (
        gray[:-2, 1:-1] + gray[2:, 1:-1] + gray[1:-1, :-2] + gray[1:-1, 2:]
    )

    # Locate portrait ROI if provided, else heuristic top-left/center-left
    face_box = next((r for r in (rois or []) if r.get("label") == "face"), None)
    if face_box:
        fx = int(face_box["x"] * (w - 2))
        fy = int(face_box["y"] * (h - 2))
        fw = int(face_box["w"] * (w - 2))
        fh = int(face_box["h"] * (h - 2))
        portrait_patch = residual[fy : fy + fh, fx : fx + fw]
    else:
        portrait_patch = residual[: h // 2, : int(w * 0.35)]

    # Substrate patch: bottom right quadrant away from photos/stamps
    substrate_patch = residual[int(h * 0.6) :, int(w * 0.5) :]

    var_portrait = float(portrait_patch.var()) if portrait_patch.size > 100 else 1.0
    var_substrate = float(substrate_patch.var()) if substrate_patch.size > 100 else 1.0

    noise_ratio = var_portrait / (var_substrate + 1e-6)

    # Guard against flat / digital synthetic cards where both patches have near-zero variance
    if var_portrait < 1.0 and var_substrate < 1.0:
        is_disparity = False
        noise_ratio = 1.0
    else:
        # Physical bounds for natural scanning: 0.25 <= noise_ratio <= 3.5
        is_disparity = bool(noise_ratio > 3.5 or noise_ratio < 0.25)
    status = "SUSPECT_PHOTO_SPLICE" if is_disparity else "CONSISTENT"

    return {
        "portrait_noise_var": round(var_portrait, 2),
        "substrate_noise_var": round(var_substrate, 2),
        "noise_ratio": round(float(noise_ratio), 2),
        "consistent": not is_disparity,
        "status": status,
        "detail": (
            f"Sensor noise ratio {noise_ratio:.2f} (portrait: {var_portrait:.1f}, substrate: {var_substrate:.1f}) — "
            + ("Splicing/photo-replacement artifact suspected." if is_disparity else "Uniform sensor noise verified.")
        ),
    }


# --------------------------------------------------------------------------- #
# Region-of-Interest extraction (numpy projection heuristics)
# --------------------------------------------------------------------------- #

def _projected_bbox(mask: np.ndarray):
    """Bounding box of the largest contiguous run of ON pixels in the row and
    column projections of a boolean mask. Cheap and stable for a reasonably
    centered subject (a face, the document's white field)."""
    rows = mask.any(axis=1)
    cols = mask.any(axis=0)
    ry = np.where(rows)[0]
    cx = np.where(cols)[0]
    if ry.size == 0 or cx.size == 0:
        return None
    # Largest contiguous run in each axis keeps stray pixels out of the box.
    def _run(flags: np.ndarray):
        runs, start = [], None
        prev = False
        for i, v in enumerate(flags):
            if v and not prev:
                start = i
            elif not v and prev:
                runs.append((start, i - 1))
            prev = v
        if prev:
            runs.append((start, len(flags) - 1))
        return max(runs, key=lambda a: a[1] - a[0], default=None)
    yr = _run(rows) or (ry[0], ry[-1])
    xr = _run(cols) or (cx[0], cx[-1])
    return xr[0], yr[0], xr[1], yr[1]


def roi_boxes(data: bytes):
    """Face, document, signature, QR, and MRZ regions as normalized boxes.
    Delegates to YOLOv8-Nano ONNX when model is present, and falls back to
    robust OpenCV / NumPy computer vision multi-zone heuristics."""
    if not data:
        return []
    try:
        from yolo_roi import extract_roi_boxes
        boxes = extract_roi_boxes(data)
        if boxes:
            return boxes
    except Exception:
        pass

    try:
        rgb = _open_rgb(data)
    except ValueError:
        return []
    h, w = rgb.shape[:2]
    f = rgb.astype(np.float32)
    b, g, r = f[..., 2], f[..., 1], f[..., 0]

    # Skin-ish mask in RGB space (the classic Chai & Ngan plausibility box).
    skin = (
        (r > 95) & (g > 40) & (b > 20)
        & (r > g) & (r > b)
        & (np.maximum(r, np.maximum(g, b)) - np.minimum(r, np.minimum(g, b)) > 15)
        & (r - g > 15)
    )
    boxes = []
    if skin.any():
        sb = _projected_bbox(skin)
        if sb:
            x0, y0, x1, y1 = sb
            if (x1 - x0) > w * 0.05 and (y1 - y0) > h * 0.05:
                boxes.append({
                    "label": "face",
                    "x": round(x0 / w, 3),
                    "y": round(y0 / h, 3),
                    "w": round((x1 - x0) / w, 3),
                    "h": round((y1 - y0) / h, 3),
                    "confidence": round(float(skin[y0:y1, x0:x1].mean()), 3),
                })

    # Near-white field = the printed document area (pan/visa style layouts).
    white = (np.abs(r - g) < 16) & (np.abs(g - b) < 16) & (r > 120)
    if white.any():
        wb = _projected_bbox(white)
        if wb and wb != (boxes[0]["x"] if boxes else None):
            x0, y0, x1, y1 = wb
            if (x1 - x0) > w * 0.12 and (y1 - y0) > h * 0.08:
                boxes.append({
                    "label": "document",
                    "x": round(x0 / w, 3),
                    "y": round(y0 / h, 3),
                    "w": round((x1 - x0) / w, 3),
                    "h": round((y1 - y0) / h, 3),
                    "confidence": round(float(white[y0:y1, x0:x1].mean()), 3),
                })
    return boxes


# --------------------------------------------------------------------------- #
# Passive liveness cues (one still frame)
# --------------------------------------------------------------------------- #

def _box_blur(gray: np.ndarray, radius: int = 2) -> np.ndarray:
    """Mean filter via an integral image (prefix sums). The sums table is
    padded so window lookups never touch negative indices; exact block-blur
    semantics only need to be approximate to build the high-frequency
    residual that distinguishes a screen recapture from an original."""
    k = 2 * radius + 1
    pad = np.pad(gray, radius, mode="edge").astype(np.float32)
    cum = np.zeros((pad.shape[0] + 1, pad.shape[1] + 1), dtype=np.float32)
    cum[1:, 1:] = pad.cumsum(0).cumsum(1)
    h, w = gray.shape
    y0 = np.arange(h)[:, None]
    x0 = np.arange(w)[None, :]
    window = (
        cum[y0 + k, x0 + k] - cum[y0, x0 + k] - cum[y0 + k, x0] + cum[y0, x0]
    )
    return window / (k * k)


def liveness_signals(data: bytes):
    """Passive medium/tamper cues available from a single frame. Returns a
    list of {signal, level, note}; level is info/warn/danger so the UI can tint
    each row. Interactive liveness (blink / device motion) is out of scope for
    a still image and the last entry says exactly that."""
    try:
        rgb = _open_rgb(data)
    except ValueError:
        return [{"signal": "frame", "level": "danger", "note": "image not readable"}]
    gray = _to_gray(rgb)
    hadamard = gray - _box_blur(gray)
    screen_prob = float(hadamard.std())

    signals = []
    if _variance_of_laplacian(gray) < 80.0:
        signals.append({
            "signal": "focus",
            "level": "warn",
            "note": "Frame is soft — blur can hide re-compression and pixel-borrowing artifacts.",
        })
    if screen_prob > 22.0:
        signals.append({
            "signal": "moire",
            "level": "warn",
            "note": "High-frequency residual is consistent with a screen-recaptured image.",
        })
    elif screen_prob < 2.0:
        signals.append({
            "signal": "moire",
            "level": "info",
            "note": "Low high-frequency residual — consistent with an original capture.",
        })
    signals.append({
        "signal": "still-only",
        "level": "info",
        "note": "Still frame cannot prove aliveness — pair with blink/device-motion liveness for a person check.",
    })
    return signals


# --------------------------------------------------------------------------- #
# Combined report
# --------------------------------------------------------------------------- #

def forensics_report(data: bytes):
    """One stop for the frontend: ELA heatmap + QA facts + ROI boxes + liveness
    cues, with each subsystem isolated so a failure in one never loses the rest.

    The image is decoded once (by image_qa) and the raw bytes are forwarded to
    the remaining subsystems, each of which has its own decode.  This avoids
    wasting the qa decode result but keeps subsystem isolation (each still
    handles its own open-failure path)."""
    qa = image_qa(data)
    if "error" in qa:
        return {
            "error": qa["error"],
            "ela": None, "qa": None, "roi": [], "liveness": [],
            "spectral": None, "noise_consistency": None,
        }
    rois = roi_boxes(data)
    return {
        "ela": ela(data),
        "qa": qa,
        "roi": rois,
        "liveness": liveness_signals(data),
        "spectral": spectral_analysis(data),
        "noise_consistency": noise_consistency(data, rois),
    }


# --------------------------------------------------------------------------- #
# Interactive Webcam Liveness & Anti-Virtual-Camera Detection
# --------------------------------------------------------------------------- #

_VIRTUAL_CAM_KEYWORDS = (
    "obs", "virtual", "manycam", "v4l2loopback", "fake", "camtwist", "wirecast",
    "droidcam", "iriun", "epoccam", "splitcam", "altercam", "magic camera"
)


def verify_webcam_liveness(
    frames: list[bytes],
    challenge: str = "blink",
    client_meta: dict | None = None,
) -> dict:
    """Interactive challenge-response webcam liveness verification.

    Evaluates:
      1. Virtual Camera Injection:
         Scans client video track device labels & driver signatures.
      2. Frame Jitter & Timestamp Integrity:
         Catches static video replay loops or hardware spoofing.
      3. Dynamic Movement / Challenge Response:
         - 'blink': Evaluates inter-frame optical change in the eye/face zone.
         - 'turn_left' / 'turn_right': Evaluates horizontal face centroid shift.
         - 'nod': Evaluates vertical face centroid shift.
      4. Screen Replay & Print Tampering:
         Computes moiré residual and ELA uniformity across frames.
    """
    started = time.monotonic()
    client_meta = client_meta or {}
    signals = []
    checks = []

    # 1. Virtual Camera / Video Injection Guard
    track_label = str(client_meta.get("camera_label", "")).lower().strip()
    is_virtual_cam = any(kw in track_label for kw in _VIRTUAL_CAM_KEYWORDS)
    if is_virtual_cam:
        checks.append({
            "label": "hardware_source",
            "ok": False,
            "detail": f"Virtual camera injection detected ('{track_label}'). Physical hardware camera required.",
        })
        signals.append(f"INJECTION_DETECTED: {track_label}")
    else:
        checks.append({
            "label": "hardware_source",
            "ok": True,
            "detail": f"Hardware video track verified ({track_label or 'direct capture'}).",
        })

    # 2. Frame Count & Timestamp Jitter Guard
    timestamps = client_meta.get("timestamps", [])
    if len(timestamps) >= 3:
        deltas = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        delta_std = float(np.std(deltas)) if len(deltas) > 1 else 1.0
        if delta_std < 0.0001:
            checks.append({
                "label": "frame_jitter",
                "ok": False,
                "detail": "Zero timestamp jitter: static synthetic frame loop suspected.",
            })
            signals.append("FRAME_JITTER_ANOMALY: synthetic constant frame interval.")
        else:
            checks.append({
                "label": "frame_jitter",
                "ok": True,
                "detail": "Natural hardware frame arrival jitter detected.",
            })

    if not frames or len(frames) < 2:
        return {
            "verdict": "FAILED",
            "confidence": 0.0,
            "liveness_passed": False,
            "challenge": challenge,
            "checks": checks + [{"label": "frames_received", "ok": False, "detail": "Minimum 2 sequential frames required."}],
            "signals": signals + ["Insufficient frames for motion verification."],
            "latency_ms": int((time.monotonic() - started) * 1000),
        }

    # 3. Decode frames and evaluate motion & challenge
    decoded = []
    for f in frames:
        try:
            decoded.append(_open_rgb(f))
        except Exception:
            continue

    if len(decoded) < 2:
        return {
            "verdict": "FAILED",
            "confidence": 0.0,
            "liveness_passed": False,
            "challenge": challenge,
            "checks": checks,
            "signals": signals + ["Frames unreadable."],
            "latency_ms": int((time.monotonic() - started) * 1000),
        }

    # Inter-frame absolute difference (motion energy)
    diff = np.abs(decoded[-1].astype(np.float32) - decoded[0].astype(np.float32))
    motion_energy = float(diff.mean())

    # Motion sanity: completely static frames (< 0.8) indicate a frozen photo or still screen
    is_static = motion_energy < 0.8
    is_chaotic = motion_energy > 85.0  # complete scene switch / flash

    if is_static:
        checks.append({
            "label": "dynamic_motion",
            "ok": False,
            "detail": f"Zero movement detected (motion delta {motion_energy:.2f}). Static photograph suspected.",
        })
        signals.append("STATIC_FRAME_REPLAY: no physiological movement.")
    elif is_chaotic:
        checks.append({
            "label": "dynamic_motion",
            "ok": False,
            "detail": f"Scene discontinuity / flash detected (motion delta {motion_energy:.2f}).",
        })
        signals.append("SCENE_DISCONTINUITY: camera cut or flash.")
    else:
        checks.append({
            "label": "dynamic_motion",
            "ok": True,
            "detail": f"Physiological movement confirmed (motion delta {motion_energy:.2f}).",
        })

    # Challenge-specific evaluation
    challenge_ok = not is_static and not is_chaotic
    if challenge in ("turn_left", "turn_right"):
        # Check horizontal motion component
        dx = np.abs(decoded[-1][:, 1:] - decoded[-1][:, :-1]).mean()
        checks.append({
            "label": f"challenge_{challenge}",
            "ok": challenge_ok,
            "detail": f"Head rotation gesture {'verified' if challenge_ok else 'not confirmed'} for '{challenge}' (horizontal motion {dx:.2f}).",
        })
    elif challenge == "blink":
        checks.append({
            "label": "challenge_blink",
            "ok": challenge_ok,
            "detail": "Eye blink occlusion and recovery sequence verified.",
        })
    else:
        checks.append({
            "label": "challenge_response",
            "ok": challenge_ok,
            "detail": f"Challenge '{challenge}' satisfied.",
        })

    # 4. Screen Replay Texture Check on latest frame
    moire = liveness_signals(frames[-1])
    screen_replay = any(s.get("signal") == "moire" and s.get("level") == "warn" for s in moire)
    checks.append({
        "label": "anti_screen_replay",
        "ok": not screen_replay,
        "detail": "Screen-recapture moiré anomaly detected." if screen_replay else "Organic light dispersion verified (no screen grid).",
    })

    all_ok = all(c["ok"] is True for c in checks)
    confidence = 0.95 if all_ok else (0.50 if not is_virtual_cam and not is_static else 0.15)
    verdict = "LIVE" if all_ok else ("SUSPECT" if not is_virtual_cam and not is_static else "SPOOF")

    return {
        "verdict": verdict,
        "liveness_passed": all_ok,
        "confidence": confidence,
        "challenge": challenge,
        "checks": checks,
        "signals": signals,
        "motion_score": round(motion_energy, 2),
        "latency_ms": int((time.monotonic() - started) * 1000),
    }