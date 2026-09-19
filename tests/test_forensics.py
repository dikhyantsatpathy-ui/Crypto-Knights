"""
Unit tests for visual forensics: ELA heatmap, YOLOv8-Nano ROI detection,
passive quality checks, and active webcam liveness with anti-virtual-camera guards.

Run:
    .venv/Scripts/python tests/test_forensics.py
"""

import io
import os
import sys
import numpy as np
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

import forensics
import yolo_roi


def _make_test_image(w=320, h=240, noise=False):
    buf = io.BytesIO()
    if noise:
        arr = np.random.randint(0, 255, (h, w, 3), dtype=np.uint8)
        img = Image.fromarray(arr)
    else:
        img = Image.new("RGB", (w, h), color=(240, 240, 240))
    img.save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def test_ela_generates_heatmap():
    data = _make_test_image()
    res = forensics.ela(data)
    assert res["engine"] == "ela"
    assert "heatmap_b64" in res
    assert len(res["heatmap_b64"]) > 50
    assert res["status"] in ("LOW", "MEDIUM", "HIGH")
    assert isinstance(res["damage_ratio"], float)
    assert len(res["overlay_grid"]) == 10
    assert len(res["overlay_grid"][0]) == 10


def test_image_qa_metrics():
    data = _make_test_image(w=400, h=300)
    qa = forensics.image_qa(data)
    assert qa["width"] == 400
    assert qa["height"] == 300
    assert isinstance(qa["blur_est"], float)
    assert "blurry" in qa
    assert "overexposed" in qa


def test_yolo_roi_extraction():
    data = _make_test_image(w=500, h=350)
    boxes = yolo_roi.extract_roi_boxes(data)
    assert isinstance(boxes, list)
    assert len(boxes) >= 1
    doc_box = next((b for b in boxes if b["label"] == "document"), None)
    assert doc_box is not None
    assert 0.0 <= doc_box["x"] <= 1.0
    assert 0.0 <= doc_box["w"] <= 1.0


def test_webcam_liveness_normal_live():
    # 2 slightly differing frames simulating organic human movement
    f1 = _make_test_image(w=160, h=160)
    # Slightly modified second frame
    buf = io.BytesIO()
    img = Image.new("RGB", (160, 160), color=(225, 220, 215))
    img.save(buf, format="JPEG", quality=85)
    f2 = buf.getvalue()

    meta = {
        "camera_label": "Integrated FaceTime HD Camera",
        "timestamps": [1000.0, 1033.2, 1066.8],
    }
    res = forensics.verify_webcam_liveness([f1, f2], challenge="blink", client_meta=meta)
    assert res["liveness_passed"] is True
    assert res["verdict"] == "LIVE"
    assert any(c["label"] == "hardware_source" and c["ok"] is True for c in res["checks"])
    assert any(c["label"] == "dynamic_motion" and c["ok"] is True for c in res["checks"])


def test_webcam_liveness_virtual_camera_rejected():
    f1 = _make_test_image(w=160, h=160)
    f2 = _make_test_image(w=160, h=160)
    meta = {
        "camera_label": "OBS Virtual Camera (v4l2)",
        "timestamps": [1000.0, 1033.0, 1066.0],
    }
    res = forensics.verify_webcam_liveness([f1, f2], challenge="blink", client_meta=meta)
    assert res["liveness_passed"] is False
    assert res["verdict"] == "SPOOF"
    assert any("INJECTION_DETECTED" in s for s in res["signals"])


def test_webcam_liveness_static_replay_rejected():
    # Identical frames simulating a frozen photograph
    f1 = _make_test_image(w=160, h=160)
    meta = {
        "camera_label": "USB WebCam",
        "timestamps": [1000.0, 1033.0, 1066.0],
    }
    res = forensics.verify_webcam_liveness([f1, f1], challenge="blink", client_meta=meta)
    assert res["liveness_passed"] is False
    assert any(c["label"] == "dynamic_motion" and c["ok"] is False for c in res["checks"])


def _run():
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok  {name}")
            except Exception as e:
                failures += 1
                print(f"FAIL  {name}: {e}")
    print(f"\n{len([1 for k in globals() if k.startswith('test_') and callable(globals()[k])]) - failures} passed, {failures} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    _run()
