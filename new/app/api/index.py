"""Vercel serverless entrypoint.

Deploys the whole FastAPI app (API routes + index.html / main.js serving) as a
single Python function. Set the same environment variables you keep in .env
(DATABASE_URL, MASTER_VAULT_KEY, GOOGLE_CLIENT_ID, ...) under your Vercel
project's settings; python-dotenv already tolerates their absence here.

The FastAPI instance lives in `app/main.py`; this file is the thin handler that
Vercel invokes, so it must import from the `app` package (works when Vercel sets
the CWD to the project root and `app/` is on the import path).
"""
import os
import sys

# Make the project root importable so `import app` resolves even if Vercel's
# runner sets a different working directory.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # -> new/
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from app.main import app as app  # noqa: E402  (FastAPI instance)