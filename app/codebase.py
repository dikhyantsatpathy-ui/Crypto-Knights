"""
Codebase-backed context for the nocap guide chatbot.

Scans the project's own repository once (lazily, cached in memory) and builds a
lightweight searchable index of every source and doc file. Each /api/chat
question is scored against that index; the most relevant files are pulled out
with the lines around each match and injected into the Gemini system prompt as
a CODE CONTEXT section. That lets the model answer from the actual code —
naming the file path and line — instead of a hand-written fact sheet.

The index is built from the repo root (parent of the `app/` package), so it
works identically when run locally (python app/main.py) and on Vercel
(api/index.py -> main.py). Secrets, build output, junk and the abandoned FIX/
refactor are excluded.
"""

import os
import re
import threading

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that never belong in the code context.
SKIP_DIRS = {
    ".agents", ".backup", ".git", ".opencode", ".playwright-mcp", ".pytest_cache",
    ".ruff_cache", ".venv", "_backup", "build", "data", "dist", "new", "node_modules",
    "scripts", "smoke", "tasks", "temp", "tmp", "FIX", "__pycache__",
}

# Files / extensions that never belong in the code context.
SKIP_FILE_PREFIXES = (".env",)
SKIP_FILE_NAMES = {
    "bun.lock", "index.html", "package-lock.json",  # built bundle + lockfiles
}
SKIP_FILE_EXTS = {
    ".bat", ".bin", ".exe", ".gif", ".ico", ".jpeg", ".jpg", ".lock", ".log",
    ".otf", ".pdf", ".png", ".pyc", ".sh", ".ttf", ".woff", ".woff2",
}
INCLUDE_EXTS = {
    ".css", ".html", ".js", ".json", ".jsx", ".md", ".py", ".toml", ".ts",
    ".tsx", ".txt", ".yaml", ".yml",
}

# Stopwords that add no signal when ranking files for a query.
_STOPWORDS = {
    "a", "an", "and", "are", "can", "do", "does", "for", "from", "how", "i",
    "in", "is", "it", "me", "my", "of", "on", "or", "that", "the", "this",
    "to", "what", "when", "where", "which", "who", "why", "with", "you", "your",
}

_MAX_FILE_CHARS = 250_000
_TOP_K = 6
_SNIPPET_RADIUS = 18        # lines before/after a hit line
_MAX_SNIPPET_CHARS = 7_000  # per selected file
_MAX_CONTEXT_CHARS = 38_000 # total injected into the prompt

_TOKEN_RE = re.compile(r"[a-z0-9_]+")

_lock = threading.Lock()
_index: list[dict] | None = None


def _iter_source_files():
    """Yield (rel_path, abs_path) for every file that belongs to the index."""
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
            yield rel, abs_path


def _tokenize(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for tok in _TOKEN_RE.findall(text.lower()):
        counts[tok] = counts.get(tok, 0) + 1
    return counts


def _load_index():
    """Lazily scan the repo once and cache the result."""
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
            files.append({
                "rel": rel,
                "text": text,
                "tokens": _tokenize(text),
                "name_tokens": _tokenize(rel),
            })
        files.sort(key=lambda f: f["rel"])
        _index = files
        return _index


def _rank_files(question: str):
    """Score every indexed file against the query's tokens; return matches sorted best-first."""
    q_tokens = [t for t in _tokenize(question) if t not in _STOPWORDS]
    if not q_tokens:
        return []
    attempts = list(dict.fromkeys(q_tokens))  # dedupe, keep order
    scored = []
    for f in _load_index():
        score = 0.0
        for tok in attempts:
            name_hits = f["name_tokens"].get(tok, 0)
            body_hits = f["tokens"].get(tok, 0)
            if name_hits:
                score += 6.0 + name_hits * 1.5          # filename match weighs more
            if body_hits:
                score += 1.0 + min(body_hits, 6)        # capped body hits
        if score > 0:
            scored.append((score, f))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored[:_TOP_K]]


def _snippets(f: dict, question: str) -> str:
    """Return the most relevant slice(s) of a file for the question."""
    q_tokens = {t for t in _tokenize(question)}
    lines = f["text"].splitlines()
    if not lines:
        return ""
    hits = {
        i for i, ln in enumerate(lines)
        if any(t in ln.lower() for t in q_tokens)
    }
    if len(f["text"]) <= _MAX_SNIPPET_CHARS and not hits:
        # Small file, no direct hit: hand over the whole thing.
        return f["text"][:_MAX_SNIPPET_CHARS]

    if not hits:
        # No direct hit (e.g. broad question): show the file header / docstring area.
        header = lines[:40]
        return "\n".join(header)[:_MAX_SNIPPET_CHARS]

    selected: set[int] = set()
    for i in hits:
        for j in range(max(0, i - _SNIPPET_RADIUS), min(len(lines), i + _SNIPPET_RADIUS + 1)):
            selected.add(j)
    width = len(str(len(lines)))
    out: list[str] = []
    used = 0
    for i in sorted(selected):
        line = f"{i + 1:>{width}}| {lines[i]}"
        if used + len(line) + 1 > _MAX_SNIPPET_CHARS:
            break
        out.append(line)
        used += len(line) + 1
    return "\n".join(out)


def codebase_context(question: str) -> str:
    """Build the CODE CONTEXT block for the chat prompt from a user question."""
    if not question or not question.strip():
        return ""
    top = _rank_files(question)
    if not top:
        return ""
    if not _load_index():
        return ""

    parts: list[str] = []
    used = 0
    for f in top:
        snippet = _snippets(f, question)
        if not snippet.strip():
            continue
        block = f"### FILE: {f['rel']}\n{snippet}"
        if used + len(block) + 2 > _MAX_CONTEXT_CHARS:
            break
        parts.append(block)
        used += len(block) + 2
    if not parts:
        return ""
    return ("Below is the ACTUAL SOURCE CODE of this project, retrieved for the current "
            "question. Read it carefully and answer from it. When you reference a detail "
            "from the code, cite the file path and line numbers (e.g. app/main.py:122). "
            "If the question touches something not shown here, stay honest and say what the "
            "code you can see does.\n\n" + "\n\n".join(parts))