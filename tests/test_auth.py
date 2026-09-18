"""
Tests for the session-token scheme (app/main.py).

The session cookie is a self-contained HMAC token `email::exp::sig`:
fresh tokens authenticate, tampered/expired/legacy tokens get 401.

Run either way:
    python tests/test_auth.py        # plain asserts
    pytest tests/test_auth.py        # pytest runner
"""

import hashlib
import hmac
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

from fastapi import HTTPException
from starlette.requests import Request

from main import MASTER_VAULT_KEY, get_current_admin, make_session_token


def _req_with_cookie(token):
    scope = {"type": "http", "headers": [(b"cookie", f"nischay_session={token}".encode())]}
    return Request(scope)


def _req_without_cookie():
    return Request({"type": "http", "headers": []})


def _expect_401(request):
    try:
        get_current_admin(request)
    except HTTPException as e:
        assert e.status_code == 401, f"expected 401, got {e.status_code}"
        return e.detail
    raise AssertionError("expected HTTPException(401)")


def test_fresh_token_authenticates():
    token = make_session_token("Officer@Example.com")
    assert token.count("::") == 2
    assert get_current_admin(_req_with_cookie(token)) == "officer@example.com"


def test_tampered_signature_rejected():
    token = make_session_token("officer@example.com")
    email, exp, _sig = token.split("::")
    bad = f"{email}::{exp}::{'0' * 64}"
    _expect_401(_req_with_cookie(bad))


def test_tampered_email_rejected():
    token = make_session_token("officer@example.com")
    _email, exp, sig = token.split("::")
    _expect_401(_req_with_cookie(f"attacker@example.com::{exp}::{sig}"))


def test_expired_token_rejected():
    email = "officer@example.com"
    exp = str(int(time.time()) - 60)
    sig = hmac.new(MASTER_VAULT_KEY, f"{email}::{exp}".encode(), hashlib.sha256).hexdigest()
    detail = _expect_401(_req_with_cookie(f"{email}::{exp}::{sig}"))
    assert "expired" in detail.lower()


def test_legacy_two_part_token_rejected():
    email = "officer@example.com"
    sig = hmac.new(MASTER_VAULT_KEY, email.encode(), hashlib.sha256).hexdigest()
    _expect_401(_req_with_cookie(f"{email}::{sig}"))


def test_missing_cookie_rejected():
    _expect_401(_req_without_cookie())


if __name__ == "__main__":
    fns = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print("PASS", fn.__name__)
    print(f"{passed}/{len(fns)} tests passed")
