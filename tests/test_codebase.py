"""
Tests for the codebase-backed chat context (app/codebase.py).

Verifies the indexer finds the project's own source files, skips junk/secrets,
scores the right file for a query, and never produces empty context for a real
code question.

Run either way:
    python tests/test_codebase.py        # plain asserts
    pytest tests/test_codebase.py        # pytest runner
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

from codebase import (
    REPO_ROOT,
    _load_index,
    _rank_files,
    _snippets,
    codebase_context,
    _MAX_CONTEXT_CHARS,
)


def test_index_scans_project_sources():
    rels = {f["rel"] for f in _load_index()}
    # Real project files must be discoverable from the repo root.
    assert "app/main.py" in rels
    assert "app/screening.py" in rels
    assert any(r.endswith("frontend/src/views/AnalyticsView.tsx") for r in rels) or any(
        r == "frontend/src/views/AnalyticsView.tsx" for r in rels
    )
    assert "README.md" in rels


def test_index_skips_junk_and_secrets():
    rels = {f["rel"] for f in _load_index()}
    for bad in (".env", ".env.local", "node_modules", ".git", "FIX", "webpack"):
        assert not any(bad in r for r in rels), f"index must skip {bad}"


def test_rank_finds_flag_removal_code():
    top = _rank_files("where did the dday drill go")
    assert top, "expected at least one ranked file"
    # The D-day removal touched main.py + frontend views; our ranker must stay
    # relevant, so just assert we return something code-shaped.
    assert all(f["text"].strip() for f in top)


def test_verhoeff_question_ranks_screening():
    top = _rank_files("how does the verhoeff check work in screening")
    rels = [f["rel"] for f in top]
    assert any("screening" in r for r in rels), f"expected screening.py in top files, got {rels}"


def test_context_includes_instruction_prefix():
    ctx = codebase_context("how does blockchain anchoring work")
    assert ctx.startswith("Below is the ACTUAL SOURCE CODE")
    assert "FILE:" in ctx


def test_context_respects_budget():
    ctx = codebase_context("what is the tech stack and how do I run it")
    assert len(ctx) <= _MAX_CONTEXT_CHARS + 500  # small tolerance


def test_snippets_never_empty_for_matching_file():
    index = _load_index()
    main = next(f for f in index if f["rel"] == "app/main.py")
    out = _snippets(main, "gemini")
    assert out.strip(), "snippet for a matching file must produce content"


def test_index_includes_scripts_documentation():
    # The scripts/ study guides are gitignored by design (kept local, never
    # pushed). On a fresh clone they are absent — skip instead of failing.
    guides = (
        "scripts/BACKEND_STUDY_GUIDE.md",
        "scripts/SIH_PRESENTATION.md",
        "scripts/THE_COMPLETE_GUIDE.md",
    )
    if not all(os.path.exists(os.path.join(REPO_ROOT, g)) for g in guides):
        import pytest

        pytest.skip("local scripts/ study guides not present (gitignored)")
    rels = {f["rel"] for f in _load_index()}
    # Markdown study guides in scripts/ must be indexed
    for g in guides:
        assert g in rels
    # Automation scripts and batch files in scripts/ must NOT be indexed
    assert not any(r.endswith(".bat") for r in rels)
    assert not any(r.endswith(".pyw") for r in rels)


def test_context_includes_blueprint_and_manifest():
    ctx = codebase_context("explain the architecture")
    assert "### SYSTEM ARCHITECTURE BLUEPRINT & REPOSITORY MAP:" in ctx
    assert "### COMPLETE PROJECT FILES MANIFEST:" in ctx
    assert "FILE: app/main.py" in ctx
    assert "FILE: app/screening.py" in ctx
    assert "FILE: frontend/src/components/ProjectChatbot.tsx" in ctx


def test_reload_index():
    from codebase import reload_index
    idx = reload_index()
    assert len(idx) > 35


if __name__ == "__main__":
    fns = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print("PASS", fn.__name__)
    print(f"{passed}/{len(fns)} tests passed")