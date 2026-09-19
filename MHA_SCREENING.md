# SIH26188 — AI-Based Fake Identity & Document Screening (MHA) — BUILD STATUS / HANDOFF

> **Status: DONE** — the four PS modules are built, Aadhaar is fully stripped,
> the suite is green (84 tests), both remotes are pushed at `a88f01a`, and the
> bundle deploys live to https://no-cap-tau.vercel.app.
> This file is the accuracy-grounded twin of `frontend/src/knowledge.ts`
> (which cites `MHA_SCREENING.md` as its source). Update it whenever the desk
> changes so the next agent can trust it.

---

## 1. THE PROBLEM STATEMENT (source of truth — do not regress)

**SIH26188 — "AI-Based Fake Identity & Document Screening System"** —
Ministry of Home Affairs, Sashastra Seema Bal (SSB), Police II Division.
Software · Miscellaneous. A **border-checkpoint document screening tool**.
The PS explicitly requires FOUR modules:

- **Module 1: OCR Extraction** — auto-extract fields from identity/travel
  documents (Passport, National ID, Driving Licence, permit documents).
- **Module 2: Document Validation** — verify extracted info against official
  document standards (check digits, format rules, checksums, expiry) and
  validate against rules + databases.
- **Module 3: Tampering Detection (core AI)** — detect digitally or physically
  altered documents: **Photo Replacement, Text Manipulation, Stamp Forgery,
  Image Metadata Analysis.**
- **Module 4: Face Verification** — document owner vs the presented person
  (live frame vs document portrait).

Expected impact accepted as the yardstick: seconds instead of minutes,
standardized screening decisions, a **risk score** for border staff, and a
**digital trail** for investigations. Expired/blacklisted documents and
identity impersonation must be caught.

> WARNING: public SIH scraper text contains a garbage "Expected Solution" line
> about "monitor and manage police assets" — a scrape artifact from a different
> PS. Ignore it. The four modules + risk score + digital trail ARE the criteria.

## 2. THE REPO — TWO SOULS, ONE SHELL

Repo `D:\mos\crypto`. FastAPI backend in `app/`, single-file React bundle in
`frontend/src` compiled to `app/static/index.html` (Vercel serves that
bundle). Windows/PowerShell environment — see §11.

The repo has two overlapping "souls":
1. **No Cap — provenance/ledger engine** (deepfake/vault/web3 lexicon). Alive
   and untouched by this build: `/api/sign*`, `/api/verify*`, ledger,
   rollback, notice board, analytics, AI chatbot (`/api/chat`).
2. **The identity-document screening desk (this project)** — the four modules
   below, orchestrated by `run_screening`.

## 3. WHAT IS DONE (git history)

- `9d8394a` **feat: SIH26188 4-module screening desk** — built the four
  modules, deleted mock registries (`verification_providers.py`) and DigiLocker
  (`digilocker_provider.py`), removed the `/api/identity/*` route suite,
  refreshed the frontend desk, migrated the DB (masked screening rows only).
- `a88f01a` **feat: drop Aadhaar/UIDAI/QR-crypto** (HEAD, pushed to `origin`
  and `crypto-knights`) — full Aadhaar strip per user directive ("completely
  lean into the direction for SIH"): removed the Aadhaar doc type, the
  Aadhaar-SecureQR `crypto_mode` toggle, the `UIDAI_AADHAAR_PUBKEY_PEM` env
  var, the Verhoeff checksum, QR decode / QR-portrait plumbing, and the
  orphaned `IdentityCheck` DB model. Screening now covers **DL / Passport /
  PAN / Voter-ID**.

## 4. LOCKED DECISIONS (as-built, supersede any earlier plan)

1. **Aadhaar is OUT.** No Aadhaar doc type, no crypto toggle, no UIDAI key, no
   Verhoeff, no QR decode, no QR portrait. (Earlier plan "keep both crypto
   paths with a toggle" is **superseded** — the user explicitly dropped it.)
2. **No fake registries, no DigiLocker.** Both provider files are deleted
   along with all `IDV_*` / `DIGILOCKER_*` env vars. The only "database
   lookup" is the honest **SHA-256 hash-only watchlist**.
3. **Doc-type scope:** verify deterministically, demystify the invigilators —
   **Passport** (ICAO 9303 TD3 MRZ check digits), **Driving Licence** (format
   rules), **PAN** (structure + PAN check-character), **Voter-ID/EPIC**
   (format). Anything else = format rules only, no fake "REGISTERED" claims.
4. **Digital trail = plain DB audit** — masked `ScreeningReport` rows +
   watchlist + opener attribution. No ledger anchoring for screenings (the
   ledger's own `crypto_mode` field on blocks is unrelated — leave it).
5. **Zero-storage contract:** raw bytes/text/photos are read, used, discarded.
   DB stores only SHA-256 hashes, masked identifiers, and explainable signals.
   MRZ zero-storage: passport validation folds the extractor's already-validated
   check digits in via `fields["mrz_valid"]` when no MRZ text is handed on.

## 5. THE PIPELINE — four thin modules (1:1 with the PS)

Orchestrated by `run_screening(db, data, filename, doc_type, checkpoint,
declared_map, screener=..., live_frame=...)` in `app/screening.py`. Response
gains a `modules` section (extraction/validation/tampering/face) beside the
existing report contract.

| Module | File | Entry point | What it does |
|---|---|---|---|
| M1 extraction | `app/extraction.py` | `extract_document(data, filename, doc_type, declared)` | pdf→pypdf text layer→`extract_fields` (identifier regexes + MRZ); image→tesseract OCR (best-effort)+MRZ parse. `declared` back-fills gaps, never shadows machine-read values. Output `{medium, fields, mrz, ocr, pdf_no_text}`. |
| M2 validation | `app/validation.py` | `validate_document(doc_type, fields, declared=None, mrz_text="", watchlist_hits=None)` | deterministic `{label, ok(True/False/None), detail}` checks per type (MRZ check digits, PAN structure/check-char, DL/voter format, expiry), plus the hash-only watchlist fold-in. `ok=None` = "inspect by eye", never a silent pass. |
| M3 tampering | `app/tampering.py` | `tamper_analysis(image_bytes, ai_detection=None, ...)` | aggregates `forensics.ela` (+ face-zone crop), `image_qa`, ROI zone boxes, metadata/EXIF fingerprints into named checks; returns `{verdict, checks, ela, roi}`. **Photo Replacement / Text Manipulation / Stamp Forgery / Metadata Analysis** all surface here as named checks. |
| M4 face | `app/face.py` | `face_verification(document_bytes=None, live_frame=None, doc_type="")` | document face ROI (from module 3 zone boxes) vs live webcam frame via `face_match.compare_faces`; `{score, match T/F/None, method, detail, checks, verdict}`. Missing live frame / no face ROI degrades to honest "UNVERIFIED / confirm by eye". |

Supporting engines (unchanged, reused): `app/mrz.py` (ICAO 9303 TD1/TD2/TD3,
`compute_mrz_check_digit`, MRZ = also visas), `app/forensics.py` (ELA,
`image_qa`, `roi_boxes`, liveness signals, `verify_webcam_liveness`),
`app/face_match.py` (dHash via Pillow — works on Vercel — + optional
`FACE_EMBED_MODEL` ONNX), `app/yolo_roi.py`, `app/detectors.py` (AI/ML
content provenance).

`app/identity.py` is now **slim**: deterministic validators only
(`verify_pan`, `verify_dl`, `verify_rc`, `verify_epic`, `verify_passport`),
`ocr_extract`, `_resolve_number`/`_extract_source_number`, `_pan_check_char`.
No Aadhaar / QR / crypto / `build_identity_report`.

`app/screening.py` helpers: `norm`, `mask`, `sha256`, `mrz_checkdigit`,
`_parse_date`, `_first_date`, `extract_mrz`, `extract_fields`,
`_match_identifiers`.

**Two separate `_FIELD_FOR` maps are intentional:** `validation.py` maps
rc→`driving_licence` (screening field keys); `identity.py` maps rc→`rc`
(declared-doc map). Do not "simplify" one into the other.

## 6. RISK ENGINE & REPORT CONTRACT

- Risk starts at **20**; module verdicts then fold in (each module is also
  explained in plain-language `reasons`):
  - M2 a deterministic check failed → **+25**
  - M3 a tampering/anomaly check failed → **+14**
  - M4 face mismatch → **+40** (strongest single signal)
  - Watchlist hit → **+60** ("reroute to a supervisory officer")
  - Ledger: exact file AUTHENTIC → **−38**; REVOKED → **+32**
  - Other signals: expired documents, AI-suspected content, JSON-wrapped
    media, metadata issues, date inconsistencies etc. in the ±3…±30 band.
  - Floor: if risk ≤ 30 and coverage < 0.4 and nothing identified →
    **forced to 34** (never CLEAR on an empty evidence base).
- Clamped 0–100; verdict = `_grade`: **PASS / REVIEW / FLAG**; confidence =
  `min(0.98, 0.45 + coverage*0.5)`.
- Report `modules.extraction` = `{ran, medium, mrz, ocr, document_aware}`;
  `modules.validation` = `{verdict, checks}`; `modules.tampering` =
  `{verdict, checks, ela{status,damage_ratio,mean_diff,latency_ms},
  heatmap_b64, overlay_grid, roi}`; `modules.face` = verdict + match + checks.
- Persisted `ScreeningReport` row keeps the queue/adjudication/watchlist flow.
  Adjudication (supervisory CLEAR/FLAG + note) is part of the digital trail.

## 7. ROUTES (`app/main.py`)

Screening family (all live, verified): `POST /api/screen`,
`GET /api/screen/queue`, `GET /api/screen/reports/{report_id}`,
`POST /api/screen/reports/{report_id}/adjudicate`,
`GET /api/screen/watchlist`, `POST /api/screen/watchlist/add`,
`POST /api/screen/watchlist/remove`.

`/api/screen` form fields: `file`, `live_frame` (optional webcam blob),
`doc_type` (default `"other"`), `checkpoint`, `declared` (JSON map). **No
`crypto` field** — Aadhaar mode is gone.

Deleted (do not resurrect): `/api/identity/meta`, `/api/identity/verify`,
`/api/identity/registry-check`, `/api/identity/liveness/verify`,
`/api/identity/forensics/ela`. `main.py` no longer imports from
`identity` for reports. Stray `IdentityCheck` class + `identity_checks`
table model removed from code (live table row relic harmless).

Provenance/ledger/auth/chat routes from the No Cap soul are untouched:
`/api/sign*`, `/api/verify*`, `/api/ledger`, `/api/analytics*`,
`/api/network`, `/api/stats`, `/api/chat`, `/api/admin/*`, watch-if-you-touch.

## 8. FRONTEND (`frontend/src/`, ships as `app/static/index.html`)

- `views/AuthorityView.tsx`: the **ScreeningDesk is the single screen-desk
  UI** — upload (pdf/image), doc-type select (`SCREEN_DOC_TYPES` =
  pan/passport/driving_licence/voter_id/other; default **passport**),
  checkpoint, optional **"capture live face"** (webcam blob → `live_frame`),
  result card with M1–M4 module panels + per-check tone
  (`MODULE_VERDICT_TONE`), ELA heatmap overlay, queue, adjudication, and
  hash-only watchlist. No crypto toggle.
- `api.ts`: `screenDocument(file, docType, checkpoint, declared?, liveFrame?)`
  builds the multipart form; `ScreenModuleExtraction` has `ocr`/`mrz` but **no**
  `qr_payload_present`; `ScreenModuleValidation` has **no** `crypto_mode`.
- `app/explain.tsx` + `knowledge.ts`: chatbot/explain copy updated — no Aadhaar,
  screening described as passport/DL/PAN/voter-ID with ICAO 9303 MRZ checks.
- `npm run build` = `tsc --noEmit && vite build` (singlefile) → regenerates
  `app/static/index.html`.

## 9. DB MODELS (`app/main.py`)

`ScreeningReport` (masked fields, checks, signals, risk/verdict/confidence,
adjudication), `WatchlistEntry` (**identifier_hash + reason only**),
`SignerIdentity` (officer roles, super-admin). Ledger blocks etc. for the No
Cap soul. Migrations run at startup; the migration startup was fixed to run
each statement in its own transaction (~5s import) — do not reintroduce a
single outer transaction.

## 10. ENVIRONMENT (`app/main.py` reads via os.environ)

Core: `DATABASE_URL`, `MASTER_VAULT_KEY`, `GOOGLE_CLIENT_ID`,
`ALLOWED_DOMAINS`/`ALLOWED_EMAILS`/`SUPER_ADMINS`, `WEB3_RPC_URL`,
`WALLET_PRIVATE_KEY`, `PINATA_JWT`, `BLOCKCHAIN_EXPLORER_URL`,
`KEEPALIVE_INTERVAL`, `GEMINI_API_KEY` (chat), `FACE_EMBED_MODEL`
(face_match; unset → Pillow dHash whole-image). **Removed:** all `IDV_*`,
`DIGILOCKER_*`, `UIDAI_AADHAAR_PUBKEY_PEM`. See `.env.example`.

## 11. CONVENTIONS / GOTCHAS (read before editing)

- **Windows PowerShell 5.1.** Use full cmdlets, single-quoted strings,
  `select/Select-String`, `curl.exe`; write temp scripts for `python -c`.
- **`app/` is not a package.** Lazy cross-module imports inside functions only
  (`screening ↔ main`, `extraction→screening`, `face→face_match`,
  `validation→identity`); `screening.run_screening` imports the ORM models
  inside the function. Import cycles are the #1 trap.
- **Tesseract is NOT on Vercel.** `ocr_extract` degrades to `{ran: False,
  reason: "tesseract not installed"}` — that is the intended honest path; the
  desk still works off PDF text layers, MRZ, and declared fields.
- **Face model:** leave `FACE_EMBED_MODEL` unset in prod (whole-image dHash)
  unless you also install `onnxruntime` on the worker.
- **Ledger `crypto_mode`** in `api.ts`/`main.py`/`AuthorityView.tsx` is the
  provenance ledger's signature-mode field — unrelated to screening. Do not
  remove it (grep's "crypto_mode" will keep matching it; that is expected).
- Auto-format line endings: do not hand-edit `app/static/index.html`.

## 12. TEST & SHIP RECIPE (proven green at `a88f01a`)

```
python -m pytest -q            # 84 passed
python -m pyflakes app/... tests/...   # zero warnings
cd frontend && npm run build   # regenerates ../app/static/index.html
git add -A && git commit -m "..." && git push origin main && git push crypto-knights main
```

Remotes: `origin` = Veri_source.git, `crypto-knights` = Crypto-Knights.git
(both at `a88f01a`). Live: https://no-cap-tau.vercel.app. Live `/api/screen`
requires an admin session cookie (anonymous POST → `{"detail":"ACCESS DENIED:
Missing or invalid secure session cookie."}`). Tests: `test_screening.py`,
`test_identity.py` (validators, no Aadhaar), `test_mrz.py`, `test_forensics.py`,
`test_face_match.py`, `test_detectors.py`, `test_auth.py`, `test_codebase.py`.

## 13. THE DEMO STORY — "how do I believe it?"

At a checkpoint an officer uploads a document (passport/DL/PAN/voter-ID),
optionally a live webcam frame, and in seconds gets, in plain language:
(a) M1 fields extracted, (b) M2 validity per official standards — **check-digit
math fails when one digit flips**, (c) M3 tampering signals with an **ELA
heatmap** glowing on a re-saved / photo-swapped scan, (d) M4 face-match verdict
across document portrait vs live capture, (e) a **watchlist hit flagged
instantly without ever storing the raw identifier**, all landing in a masked
audit row with a 0–100 **risk score** + PASS/REVIEW/FLAG + supervisory
adjudication.

## 14. OPEN IDEAS (not built — conscious yays/nays)

- **Visa** as a first-class doc type: `mrz.py` already parses TD2 (visas), but
  there is no `verify_visa` and no UI option. Would need a validator + type in
  `VALIDATORS`/`SCREEN_DOC_TYPES`. **Deliberately deferred** — PS names Visa in
  M1 extraction; worth adding before judging if the demo needs it.
- **Cloud OCR on Vercel** for image-only passports (currently honest degrade).
- Production-grade face embeddings (`FACE_EMBED_MODEL`) on a worker.