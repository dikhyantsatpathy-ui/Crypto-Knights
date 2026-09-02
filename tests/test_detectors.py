"""
Smoke tests for the AI-content-detection layer.

Run either way (no deps beyond what the app already needs):
    python tests/test_detectors.py        # plain asserts
    pytest tests/test_detectors.py        # pytest runner
"""

import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

import numpy as np
from PIL import Image, PngImagePlugin, ImageDraw

from detectors import detect_image, explain
from detectors.document_aware import looks_like_scanned_document


def _png(pixel=None, software=None, size=(64, 64)):
    rng = np.random.RandomState(seed=1)
    arr = (pixel if pixel is not None else rng.randint(0, 255, size + (3,))).astype("uint8")
    buf = io.BytesIO()
    info = PngImagePlugin.PngInfo()
    if software:
        info.add_text("Software", software)
    Image.fromarray(arr).save(buf, format="PNG", **({"pnginfo": info} if software else {}))
    return buf.getvalue()


def test_empty_never_raises():
    r = detect_image(b"", "x.png")
    assert r["ran"] is False and r["ai_score"] == 0


def test_corrupt_never_raises():
    r = detect_image(b"\xff\xd8\xff", "c.jpg")
    assert r["ai_score"] == 0


def test_garbage_bytes_never_raise():
    for n in (1, 3, 10, 1000, 100000):
        r = detect_image(os.urandom(n), "r.bin")
        assert 0 <= r["ai_score"] <= 100
        assert isinstance(r["latency_ms"], int)


def test_ai_tagged_is_flagged():
    r = detect_image(_png(software="stable-diffusion-webui"), "ai.png")
    assert r["ai_suspected"] is True and r["ai_score"] >= 50
    assert isinstance(explain(r), str) and len(explain(r)) > 10


def test_clean_treated_as_ran():
    r = detect_image(_png(), "clean.png")
    assert "ran" in r


def test_score_bounds_and_type():
    r = detect_image(_png(software="midjourney"), "mj.png")
    assert isinstance(r["ai_score"], int) and 0 <= r["ai_score"] <= 100


def test_contract_keys():
    r = detect_image(_png(), "x.png")
    for k in ("ran", "ai_suspected", "ai_score", "model", "provider", "explanation", "latency_ms", "raw"):
        assert k in r


def _doc_image(w=1000, h=1300, lines=40):
    img = Image.new("L", (w, h), 248)
    d = ImageDraw.Draw(img)
    for i in range(lines):
        d.text((60, 50 + i * 28), "SPECIMEN OFFICIAL NOTICE - text heavy page content", fill=20)
    return img


def test_scanned_document_detected():
    assert looks_like_scanned_document(_png_doc()) is True


def _png_doc():
    b = io.BytesIO()
    _doc_image().save(b, format="PNG")
    return b.getvalue()


def test_scanned_doc_returns_document_verdict():
    r = detect_image(_png_doc(), "notice.png")
    assert r["provider"] == "document"
    assert r["ran"] is False and r["ai_score"] == 0


def test_document_verdict_on_photo_false():
    # A photo/noise image must NOT be misclassified as a document.
    assert looks_like_scanned_document(_png()) is False


def test_document_verdict_on_ai_art_false():
    # An AI-art-style colourful gradient must NOT be a document.
    g = np.zeros((512, 512, 3)).astype("uint8")
    v = np.linspace(0, 255, 512).astype("uint8")
    for i in range(512):
        g[i, :, :] = v[i]
    b = io.BytesIO()
    Image.fromarray(g).save(b, format="PNG")
    assert looks_like_scanned_document(b.getvalue()) is False


if __name__ == "__main__":
    fns = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print("PASS", fn.__name__)
    print(f"{passed}/{len(fns)} tests passed")