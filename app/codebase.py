"""
Codebase-backed context for the nocap guide chatbot.

Scans the project's own repository (lazily, cached in memory) and builds an authoritative,
full-visibility database of every source file, configuration, database model, API route,
frontend component, cryptographic routine, and documentation guide.

Every /api/chat query receives the COMPLETE CODEBASE DATABASE in Gemini's 1-million-token
context window. Files most relevant to the query are prioritized at the top of the context
block right after the Architectural Blueprint, followed by the rest of the repository.
Every file is injected with 1-based line numbers, allowing the AI to pinpoint exact lines
(e.g., `app/main.py:1124`, `frontend/src/components/VerdictCard.tsx:42`).
"""

import os
import re
import threading

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that never belong in the code context.
# Note: 'scripts' is now permitted for documentation guides (.md, .txt).
# 'static' is skipped because app/static/index.html is a compiled/minified bundle.
SKIP_DIRS = {
    ".agents", ".backup", ".git", ".opencode", ".playwright-mcp", ".pytest_cache",
    ".ruff_cache", ".venv", "_backup", "build", "data", "dist", "new", "node_modules",
    "smoke", "tasks", "temp", "tmp", "FIX", "__pycache__", "static",
}

# Files / extensions that never belong in the code context.
SKIP_FILE_PREFIXES = (".env",)
SKIP_FILE_NAMES = {
    "bun.lock", "package-lock.json",
}
SKIP_FILE_EXTS = {
    ".bat", ".bin", ".exe", ".gif", ".ico", ".jpeg", ".jpg", ".lock", ".log",
    ".otf", ".pdf", ".png", ".pyc", ".sh", ".ttf", ".woff", ".woff2", ".pyw",
}
INCLUDE_EXTS = {
    ".css", ".html", ".js", ".json", ".jsx", ".md", ".py", ".toml", ".ts",
    ".tsx", ".txt", ".yaml", ".yml", ".sql",
}

# Stopwords that add no signal when ranking files for a query.
_STOPWORDS = {
    "a", "an", "and", "are", "can", "do", "does", "for", "from", "how", "i",
    "in", "is", "it", "me", "my", "of", "on", "or", "that", "the", "this",
    "to", "what", "when", "where", "which", "who", "why", "with", "you", "your",
}

_MAX_FILE_CHARS = 350_000
_MAX_CONTEXT_CHARS = 2_500_000  # Comfortably holds 100% of the entire codebase and docs

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_CAMEL_RE = re.compile(r"([a-z])([A-Z])")

_lock = threading.Lock()
_index: list[dict] | None = None


def _iter_source_files():
    """Yield (rel_path, abs_path) for every source and doc file that belongs to the index."""
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn in SKIP_FILE_NAMES or fn.startswith(SKIP_FILE_PREFIXES):
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_FILE_EXTS or ext not in INCLUDE_EXTS:
                continue
            abs_path = os.path.join(dirpath, fn)
            rel = os.path.relpath(abs_path, REPO_ROOT).replace("\\", "/")

            # For scripts/ directory, only include documentation guides (.md, .txt)
            if rel.startswith("scripts/") and ext not in (".md", ".txt"):
                continue

            # Don't index temporary or test artifacts from root
            if rel.startswith("_tmp_"):
                continue

            yield rel, abs_path


def _tokenize(text: str) -> dict[str, int]:
    """Tokenize text into lower-case keywords, splitting camelCase, snake_case, and paths."""
    counts: dict[str, int] = {}
    # Split camelCase before regular token extraction
    expanded = _CAMEL_RE.sub(r"\1 \2", text)
    for tok in _TOKEN_RE.findall(expanded.lower()):
        if len(tok) > 1:
            counts[tok] = counts.get(tok, 0) + 1
    return counts


def reload_index() -> list[dict]:
    """Force re-scan and reload of the codebase index."""
    global _index
    with _lock:
        _index = None
    return _load_index()


def _load_index() -> list[dict]:
    """Lazily scan the repo once, precompute line numbers & blocks, and cache in memory."""
    global _index
    if _index is not None:
        return _index
    with _lock:
        if _index is not None:
            return _index
        files = []
        for rel, abs_path in _iter_source_files():
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read(_MAX_FILE_CHARS)
            except OSError:
                continue
            if not text.strip():
                continue
            lines = text.splitlines()
            width = len(str(len(lines)))
            snippet = "\n".join(f"{i + 1:>{width}}| {ln}" for i, ln in enumerate(lines))
            block = (
                f"================================================================================\n"
                f"FILE: {rel}\n"
                f"================================================================================\n"
                f"{snippet}"
            )
            files.append({
                "rel": rel,
                "text": text,
                "line_count": len(lines),
                "snippet": snippet,
                "block": block,
                "manifest_entry": f"- `{rel}` ({len(lines)} lines)",
                "tokens": _tokenize(text),
                "name_tokens": _tokenize(rel),
            })
        files.sort(key=lambda f: f["rel"])
        _index = files
        return _index


def _rank_files(question: str) -> list[dict]:
    """Score every indexed file against the query's tokens; return matches sorted best-first."""
    q_tokens = [t for t in _tokenize(question) if t not in _STOPWORDS]
    all_files = _load_index()
    if not q_tokens:
        return all_files
    attempts = list(dict.fromkeys(q_tokens))  # dedupe, preserve order
    scored = []
    for f in all_files:
        score = 0.0
        for tok in attempts:
            name_hits = f["name_tokens"].get(tok, 0)
            body_hits = f["tokens"].get(tok, 0)
            if name_hits:
                score += 8.0 + name_hits * 2.0
            if body_hits:
                score += 1.0 + min(body_hits, 10)
        if score > 0:
            scored.append((score, f))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored]


def _snippets(f: dict, question: str = "") -> str:
    """Return the precomputed line-numbered snippet in O(1)."""
    return f.get("snippet") or f["text"]


def _architecture_blueprint() -> str:
    """Return a high-level system architectural blueprint summarizing the repository layout."""
    return (
        "### SYSTEM ARCHITECTURE BLUEPRINT & REPOSITORY MAP:\n"
        "The project is structured into clear architectural layers:\n\n"
        "1. **Core Backend (`app/main.py`)**: Built with FastAPI & SQLAlchemy, organized into 8 strict Columns:\n"
        "   - Column 1 (Env & DB Config): DB engines (PostgreSQL / SQLite fallback), pooling, secrets.\n"
        "   - Column 2 (Database Models): `LedgerBlock`, `AuthorityKey`, `RevocationEntry`, `WatchlistEntry`, `AuditLog`.\n"
        "   - Column 3 (Cryptography & KMS Vault): ECDSA secp256k1 signing, AES-256-GCM vault key encryption, HKDF key derivation.\n"
        "   - Column 4 (Forensics & Web3 Anchoring): Merkle tree calculation, Sepolia/Polygon L2 anchor broadcasts (`NOCAP_ROOT:<root>`).\n"
        "   - Forensics Engine: ELA (Error Level Analysis), copy-move detector, JPEG ghosting, metadata traps (ID3/EXIF/PDF).\n"
        "   - Column 5 (FastAPI Base Routes): CORS, health checks, rate limiting, static file serving.\n"
        "   - Column 6 (Signing & Verification Engine): `/api/sign`, `/api/verify`, `/api/kill-switch` (authority revocation cascade).\n"
        "   - Emergency Notice Board: Public signed broadcasts & authority retractions.\n"
        "   - Column 7 (System Commands & Web3 Sync): Merkle sync, blockchain audit verification.\n"
        "   - Column 8 (Telemetry & Analytics): Verification metrics, fraud attempt tracking, daily counts.\n"
"   - Screening Desk (MHA SIH26188): `/api/screen/document`, watchlist lookup, ICAO 9303 MRZ check digits.\n"
         "   - AI Chatbot: `/api/chat` backed by full-codebase Gemini ingestion with line-numbered citations.\n\n"
         "2. **Forensic Identity Screening Desk (`app/screening.py`)**:\n"
         "   - Deterministic identifier validation: Passport (ICAO 9303 TD3 MRZ check digits), PAN/DL/Voter-ID structure rules.\n"
        "   - Multi-provider AI & heuristic content detection (Sightengine, local ONNX, frequency heuristics).\n"
        "   - Privacy-preserving watchlist matching using SHA-256 digests over normalized identifiers (no raw IDs stored).\n\n"
        "3. **Frontend Application (`frontend/src/`)**:\n"
        "   - `App.tsx`: Main shell, tab navigation, explain-mode toggle, responsive topbar.\n"
        "   - Views: `PublicView.tsx` (verification portal & notice board), `AuthorityView.tsx` (signing desk, kill-switch, broadcasts), `AnalyticsView.tsx` (telemetry & metrics).\n"
        "   - Components: `VerifyPanel.tsx` (drag-and-drop verification), `VerdictCard.tsx` (verdict rendering), `NoticeBoard.tsx` (signed alerts), `NetworkMap.tsx`, `Charts.tsx`, `ProjectChatbot.tsx` (AI guide).\n"
        "   - Utilities: `api.ts` (API client), `explain.tsx` (interactive UI guidance tooltips), `knowledge.ts` (curated offline fallback).\n\n"
        "4. **Documentation & Study Guides (`scripts/`, `README.md`)**:\n"
        "   - Comprehensive deep-dives: `THE_COMPLETE_GUIDE.md`, `BACKEND_STUDY_GUIDE.md`, `CODE_WALKTHROUGH.md`, `SIH_PRESENTATION.md`, `MHA_SCREENING.md`.\n"
    )


def codebase_context(question: str) -> str:
    """Build the complete CODE CONTEXT block containing the entire project codebase database."""
    files = _load_index()
    if not files:
        return ""

    ranked = _rank_files(question)
    ranked_set = {f["rel"] for f in ranked}
    remaining = [f for f in files if f["rel"] not in ranked_set]
    ordered_files = ranked + remaining

    blueprint = _architecture_blueprint()
    manifest = "### COMPLETE PROJECT FILES MANIFEST:\n" + "\n".join(f["manifest_entry"] for f in ordered_files)

    parts: list[str] = [blueprint, manifest]
    used = len(blueprint) + len(manifest) + 10

    for f in ordered_files:
        block = f["block"]
        if used + len(block) + 4 > _MAX_CONTEXT_CHARS:
            break
        parts.append(block)
        used += len(block) + 4

    return (
        "Below is the ACTUAL SOURCE CODE DATABASE of the entire project repository. "
        "The entire codebase across backend, frontend, database schemas, cryptographic vaults, "
        "identity screening algorithms, verification pipelines, configuration, and documentation "
        "guides is included in full below with 1-based line numbers. "
        "Every single file is accessible to you. When answering, search and cite exact file paths "
        "and line numbers (e.g. `app/main.py:1124-1140` or `frontend/src/components/VerdictCard.tsx:35`). "
        "Be technically rigorous, precise, and directly quote code snippets when explaining logic.\n\n"
        + "\n\n".join(parts)
    )