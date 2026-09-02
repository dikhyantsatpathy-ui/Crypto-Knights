"""Root ASGI entrypoint for Vercel's native FastAPI detection.

Vercel auto-detects a FastAPI app exported as `app` from a root-level
`main.py` and forwards every request's ORIGINAL path into it (no rewrites
needed), which is why /api/* and / keep working. Re-export from app/main.py.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from app.main import app as app  # noqa: E402  (FastAPI instance)