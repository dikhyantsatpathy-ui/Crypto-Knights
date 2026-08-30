"""Vercel serverless entrypoint.

Deploys the whole FastAPI app (API routes + index.html / main.js serving) as a
single Python function. Set the same environment variables you keep in .env
(DATABASE_URL, MASTER_VAULT_KEY, GOOGLE_CLIENT_ID, ...) under your Vercel
project's settings; python-dotenv already tolerates their absence here.
"""
from app import app as app