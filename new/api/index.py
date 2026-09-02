"""Vercel serverless entrypoint (project-root, Vercel's native api/ convention).

Because this file lives at the top-level `api/index.py`, Vercel routes the
original request path straight into the FastAPI app (no destination-path
rewriting), so /api/* and / keep their real paths and route matching works.
"""
import os
import sys

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # -> new/
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from app.main import app as app  # noqa: E402