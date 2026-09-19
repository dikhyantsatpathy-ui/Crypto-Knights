"""Face-match tests: identical portraits match, different ones don't,
garbage stays inconclusive, base64 (QR-attr form) is accepted."""

import base64
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import face_match as fm  # noqa: E402


def _img(kind: str) -> bytes:
    from PIL import Image, ImageDraw
    im = Image.new("RGB", (96, 96), "white")
    d = ImageDraw.Draw(im)
    if kind == "checker":
        for y in range(0, 96, 12):
            for x in range(0, 96, 12):
                if (x + y) // 12 % 2 == 0:
                    d.rectangle([x, y, x + 11, y + 11], fill="black")
    elif kind == "stripes":
        for x in range(0, 96, 8):
            d.rectangle([x, 0, x + 3, 95], fill="navy")
    elif kind == "circle":
        d.ellipse([16, 16, 80, 80], fill="firebrick")
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def test_identical_portraits_match():
    a = _img("checker")
    out = fm.compare_faces(a, a)
    assert out["match"] is True
    assert out["score"] == 100
    assert out["method"] == "phash-dhash"


def test_reencoded_same_portrait_still_matches():
    from PIL import Image
    buf = io.BytesIO()
    with Image.open(io.BytesIO(_img("checker"))) as im:
        im.save(buf, format="JPEG", quality=70)
    out = fm.compare_faces(_img("checker"), buf.getvalue())
    assert out["match"] is True


def test_different_portraits_reject():
    out = fm.compare_faces(_img("checker"), _img("stripes"))
    assert out["match"] is False
    assert out["score"] <= 75  # score is informational; the verdict is the contract


def test_garbage_stays_inconclusive():
    assert fm.compare_faces(b"not-an-image", _img("checker"))["match"] is None
    assert fm.compare_faces(None, _img("checker"))["match"] is None
    assert fm.compare_faces("", "")["match"] is None


def test_base64_qr_attr_form_accepted():
    b64 = base64.b64encode(_img("circle")).decode("ascii")
    out = fm.compare_faces(b64, _img("circle"))
    assert out["match"] is True


def test_face_match_does_not_download_a_model():
    import os
    import urllib.request
    old_model = os.environ.pop("FACE_EMBED_MODEL", None)
    old_retrieve = urllib.request.urlretrieve

    def _forbidden_retrieve(*args, **kwargs):
        raise AssertionError("face matching must not download a model")

    urllib.request.urlretrieve = _forbidden_retrieve
    try:
        out = fm.compare_faces(_img("checker"), _img("checker"))
    finally:
        urllib.request.urlretrieve = old_retrieve
        if old_model is not None:
            os.environ["FACE_EMBED_MODEL"] = old_model
    assert out["method"] == "phash-dhash"
    assert out["match"] is True


def test_capabilities_shape():
    caps = fm.face_match_capabilities()
    assert set(caps) == {"available", "method", "onnx_configured"}
    assert caps["available"] is True
    assert caps["method"] == "phash-dhash"  # no FACE_EMBED_MODEL in test env
