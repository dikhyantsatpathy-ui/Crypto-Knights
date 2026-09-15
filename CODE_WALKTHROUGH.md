# CODE_WALKTHROUGH.md — nocap, explained for a curious human

This document walks through **every** file in the project and answers four questions
about each piece: **what it does**, **why it is built that way**, **which library or
tool does the heavy lifting**, and **why that tool instead of the alternatives**.

It is written to be read out loud — by a presenter, a judge, or anyone who needs to
explain this system *by heart*. The engineering details are all here, but so is the
"why", so you can talk about it in plain words.

> Quick stats: **2 Python files** run the whole backend. **19 source files** run the
> whole frontend, compiled into ONE self-contained `app/static/index.html`.
> **32 automated tests** pass. It deploys to Vercel as a single serverless function.

---

## 0. The system in one breath

> "nocap is a public **digital notary** for official files. An institution signs a file
> with a real cryptographic key; the signature is stamped into an ordered, tamper-proof
> ledger and anchored to a blockchain. Later, anyone can drop that file back in and get
> a coloured verdict in under a second: **AUTHENTIC**, **PROVEN FAKE**, **REVOKED**, or
> **UNOFFICIAL**. The file itself is never stored — only its SHA-256 fingerprint — and a
> forensic + AI pass catches edited copies. There is also an identity-document screening
> desk (the MHA SIH 2026 entry) that checks Aadhaar/passport numbers and watches a
> hash-only police watchlist."

That sentence is the whole product. Everything below is the same sentence, expanded.

---

## 1. A file's journey — the whole story in one walkthrough

Follow one real flow end to end. This is what a judge should see:

1. **You drop a file** on the front page (`VerifyPanel.tsx` + `ui.tsx`). The browser
   itself, not the app, opens the file picker — so the flow works even when a UI layer
   like "Explain mode" is watching clicks.
2. **The browser hashes the file** locally with the Web Crypto API (`util.ts#sha256Hex`).
   The actual file never travels to the server. For files over ~3.5 MB, the browser sends
   a 2 MB sample plus the full hash in one round-trip (`VerifyPanel.tsx`), so nothing
   slows down on huge videos.
3. **The backend receives only `{ file_name, file_hash }`** and looks the hash up in its
   signing ledger (`main.py` → `POST /api/verify`). The 5-branch decision matrix decides
   the verdict (see §4).
4. **A forensic layer** checks whether the bytes carry a hidden "trap mark" that nocap
   itself injected at signing time (PDF metadata keys, MP3 `TXXX` frames, MP4 `©cmt`
   atoms). If the trap is present but the file does not match the signed digest, the bytes
   must have been changed after signing → it is a fake.
5. **An AI-detection layer** scores the media for generated/edited content. Three
   interchangeable engines live behind one switch (`DETECTION_PROVIDER`): an offline
   heuristic, a cloud API (Sightengine), or a self-hosted vision model (ONNX). PDF
   documents are routed *past* the photo models so a scanned certificate never wastes a
   photo quota.
6. **The verdict card renders** (`VerdictCard.tsx`): a colored stamp, the SHA-256 shown
   as a short human fingerprint, human-readable reasons, and a "Compare a copy" button
   that re-checks a locally modified file.
7. **Authorities** (after Google SSO, role assigned *by an admin*, never self-claimed)
   can sign, broadcast notices, revoke, and anchor to an L2 blockchain. A **kill switch**
   lets an admin revoke a compromised identity with a PIN, and revoked files instantly
   become **REVOKED** everywhere.

---

## 2. The backend — `app/main.py` (3,341 lines, one file, deliberately)

Every route, all authentication, the crypto vault, the ledger, the AI detection and the
blockchain anchoring live in **one file**. This is unusual. It is done on purpose:

- A hackathon entry has a 12-minute call with judges, not a codebase to maintain for
  years. One file means the whole story is one read-through.
- Vercel deploys it as **one serverless function** — zero microservice orchestration.
- It is broken into numbered `# ==== Column N — ... ====` sections that read like a
  script: Config → Models → Vault → Forensics → Routes → AI → Authz.

The **framework is FastAPI**. Why FastAPI and not Django, Flask, or Express?

- **Django** is batteries-included (admin, ORM, auth) but heavy and opinionated;
  its async support is bolted on. nocap only needs a few tables and a JSON API.
- **Flask** is tiny but sync-only; concurrent async work (blocking DB calls, slow
  crypto) would tie up the single event loop.
- **FastAPI** is async-native, validates request/response shapes with Pydantic at zero
  extra code, and auto-builds OpenAPI docs at `/docs`. That "shape guarantee" is exactly
  what a demo needs — a malformed request can never silently reach a handler.

The **ORM is SQLAlchemy** (the classic choice) but used in its *modern* 2.0 form
(`select()`, `update()`, `pg_insert`). The database is **Neon Postgres in production**,
**SQLite in local dev** — one flag (`_IS_SQLITE`) switches the few places that differ
(e.g. `BYTEA` vs `BLOB`), so the demo runs with zero setup and the deploy runs in the cloud.

### 2.1 Boot & configuration — "fail fast"
Loads `.env`, prepares `DATABASE_URL`, the vault key, Google client ID, optional Web3
RPC/wallet keys, and a `SUPER_ADMINS` allow-list. Missing required env vars **stop the
app immediately** instead of failing mysteriously later — a config you can trust.

### 2.2 Data model — nothing sensitive is stored
Three core tables plus helpers:

| Table | What it holds | Why designed that way |
|---|---|---|
| `SignerIdentity` | email (PK), encrypted private key + public key PEM, **role assigned by an admin**, revoke PIN, revoked flag | The private key is stored only **encrypted** (AES-GCM under a per-owner key) and **never leaves the server**. Roles come from an admin, not self-claims — the anti-impersonation guard. |
| `LedgerBlock` | `file_hash` (**UNIQUE**), signer snapshot columns, `sig_hex`, `ipfs_cid`, `tx_hash`, `merkle_root`, `is_revoked`, broadcast columns | Append-only, per-file one entry. Revocation *marks* a block (does not delete it) so history is always honest. |
| `VerificationLog` | one row per public check, incl. AI detection latency/provider | Aggregate-only telemetry (public dashboard counts, never raw rows). |
| `WatchlistEntry` (screening) | **hash-only** identifier, category, mask (`****1234`), reason, added by | Raw numbers are never persisted — privacy by construction. |

Idempotent `ALTER TABLE ADD COLUMN IF NOT EXISTS` migrations run at boot, so old
databases upgrade themselves with no manual step. A `pending_uploads` chunk table exists
because Vercel caps multipart bodies at ~4.4 MB — big signatures upload in chunks.

### 2.3 The vault & crypto
- **Key derivation:** HKDF per-owner (`derive_owner_key`) → AES-256-GCM sealing of the
  private key.
- **Signing:** SECP256R1 ECDSA (P-256) — the curve used by YubiKeys and TLS. Fast to
  verify anywhere, including in browsers.
- **Sessions:** a **stateless** cookie — literally `email::HMAC(email)` — checked with
  `hmac.compare_digest` (constant-time, so timing can't leak the tag) and `HttpOnly`
  (invisible to JavaScript). No session table, no Redis, nothing to expire server-side.
- **Why ECDSA-P256 over RSA?** P-256 signatures are far smaller (~64 bytes vs ~256+) and
  *verify* orders of magnitude faster — important when a mobile user verifies on every
  view. **Why not Ed25519?** Ed25519 is also excellent, but GPG/OpenPGP tooling and many
  institutional HSMs default to ECDSA-P256; matching that ecosystem makes the "an
  institution signed this" story more believable.

### 2.4 Forensics — the "trap"
Before signing, nocap **injects a hidden mark** into the file:
- PDF → `/Nocap_*` Info-keys inside the document dictionary.
- MP3/WAV → `TXXX` ID3 frames.
- MP4/MOV → `©cmt` metadata atom.

`inject_media_trap` / `extract_media_trap` own this. The mark is the *tell*: if a copy
still carries the trap but its digest does not match the ledger, the file was edited
after signing — the strongest proof of forgery the system can show. It is like a
watermark only the signer can have placed.

### 2.5 The routes (all `POST /api/...`)
Auth (`google`, `me`, `logout`) → role assignment (`assign_role`, super-admin only) →
signing (`sign`, plus `sign_chunk` / `sign_complete` for big files) → broadcasting
(`broadcast` text + media, `broadcasts` list, `broadcasts/delete` to retract) → verifying
(`verify`, plus chunked variants) → the kill switch (`revoke` / `reinstate` / `set_pin`)
→ ledger ops (`sync` batch-anchor, `rollback`, `dday` demo) → read-only (`ledger`,
`network`, `stats`, `analytics`, `detect/usage`).

Rate limiting uses **slowapi** (a small-throttling library on top of FastAPI): e.g. 120
checks/min per address for watchlist endpoints — demo-friendly, abuse-resistant.

**The emergency broadcast** deserves a paragraph: an authority can publish an urgent
notice (e.g. "certificate #X is void") signed with the *same* identity key. The signed
payload binds the message text **and** any embedded media (`msg + b"\x00MEDIA\x00" +
media_bytes` → sha256 → ECDSA), so nobody can detach the image and attach it to a
different claim. The narrow `_sign_text_core` runs in a **threadpool**
(`run_in_threadpool`) because a Neon round-trip is 100 ms+ — it must never block the
event loop for other users. Receipts carry `version: "nocap-v2-emergency"` so the client
knows how to interpret them. Media is constrained to image/video only (`_is_broadcast_media`),
sanitized via `_safe_filename` / `_guess_media_type`.

### 2.6 Authz helpers
`get_current_admin` and `allow_super` guard admin routes; a super admin can assign roles,
adjudicate screenings, sync, rollback. Regular signers see **only their own** ledger rows —
privilege-scoped payloads, not a shared dump.

---

## 3. The AI-detection layer (inlined in `main.py`)

Three interchangeable backends behind **`DETECTION_PROVIDER`**:

1. **heuristic** (default, offline) — inspects metadata self-tags and does a pixel-noise
   scan. Costs nothing, runs anywhere (Vercel has no GPU).
2. **sightengine** (cloud) — a commercial media-AI API with generous free tier; strong on
   face/image realism.
3. **onnx** (self-hosted vision model) — runs a real neural net on CPU via ONNX Runtime.
   Keeps data in-house but needs the model weights deployed.

Every path returns the **same shape**: `{ ran, ai_score, explanation, model, latency_ms,
provider }`. The caller never branches on which engine is installed — it is a pluggable
sensor. Documents (PDFs) are flagged `provider="document"` and **routed around** the photo
models so scanning a certificate never eats a photo-detection quota. Quota exhaustion
**fails open** — a verdict is still returned, never a dead page.

Why three engines? The demo must run offline (Vercel sandbox), the *pitch* may want a
flashy commercial API, and a *privacy-first* deployment wants self-hosting. Same code,
three costumes.

---

## 4. The verification decision matrix (the heart of the product)

In `POST /api/verify`, checks run **cheapest-first**:

1. Hash **not in ledger**, no trap → **UNSIGNED** ("No official source ever signed this").
2. Hash **not in ledger**, trap present → **PROVEN FAKE** (trap ⇒ we signed it ⇒ bytes
   changed after signing).
3. In ledger but **signer or block revoked** → **REVOKED** (kill switch / retraction).
4. In ledger + **ECDSA signature valid** → **AUTHENTIC**.
5. In ledger + **signature re-checks fail** → **PROVEN FAKE**.

Extra nuance: if the AI/forensic pass *suspends* an AUTHENTIC file (`warned`), the banner
downgrades to **SUSPICIOUS** and the CTA becomes "Check with the issuer". The stamp is
never silently all-clear.

---

## 5. The MHA screening desk — `app/screening.py` (464 lines)

This is the separate SIH 2026 entry (**PS SIH26188 — "AI-Based Fake Identity and Document
Screening System"**, MHA domain). A desk operator uploads a citizen's identity document and
the pipeline runs **Upload → Extract → Analyze → Verify → Assess Risk**:

- **Extract** fields from the photo/PDF and cross-check them against the declared values.
- **Verify** identifiers with **deterministic checksums** that run fully offline:
  **Verhoeff** for Aadhaar (a digit-checksum that catches every single-digit typo and
  every adjacent transposition), **ICAO 9303 MRZ**
  for passports, plus PAN / voter / driving-licence rules. A number that fails its
  checksum is structurally impossible, no AI needed.
- **Watchlist:** entries are stored as SHA-256 of a normalized value (`norm()`: NFKC
  unicode-normalize, strip punctuation, uppercase). Matching compares **before** hashing,
  raw numbers are never kept.
- **Assess:** a 0–100 risk score with **explainable per-reason points**, verdicts
  `CLEAR / REVIEW / FLAGGED`, and an **adjudication queue** — only supervisors/super-admins
  can finalize (clear / fraud / inconclusive).

Why this design? "AI" scores sound magical; **checksums are proof**. The combo is the
pitch: neural fuzziness for the hard cases, mathematical certainty for the common ones.

---

## 6. The frontend — 19 files → one HTML file

The frontend is **React 18 + TypeScript 5 + Vite 6**, built with **vite-plugin-singlefile**
into one self-contained `app/static/index.html` (~388 kB, all JS+CSS inlined). Why:

- **React** because it is the most widely understood component model — any judge/engineer
  can read it; state flows down, events bubble up.
- **TypeScript** because the backend already enforces request/response shapes; the
  frontend does the same for every API call — a wrong field name is a compile error, not
  a runtime crash on stage.
- **Vite** because it is near-instant to build and its proxy (`/api → localhost:8000`)
  makes same-origin dev trivial without CORS gymnastics.
- **One HTML file** because Vercel serves the whole app through one function with no
  asset pipeline; the backend can keep serving the UI even if the CDN config drifts.

### 6.1 Entry & shell

| File | What it does | Why made this way |
|---|---|---|
| `main.tsx` | Mounts the app inside providers: `ToastProvider → AuthProvider → ExplainProvider → App` | Provider order is a contract — toasts must exist before auth, auth before explain. StrictMode double-invokes effects so bugs surface in dev. |
| `App.tsx` | The shell: nav (Verify / Authority / Analytics), TopBar (session chip, **Explain toggle**, theme), footer, `<ProjectChatbot/>`. The brand mark is an upside-down cap-lock SVG | One shell = one place to add headers/footers/mode toggles. The inverted padlock says "the lock is on the viewer, not uploading", on-brand. |
| `views/gsi.ts` | Google One Tap render helper + `FALLBACK_CLIENT_ID` | Client-side **Google Identity Services**. The client ID is public by design (it identifies the *app*, not the user). `downloadReceiptJson` saves a signed receipt per broadcast. |
| `views/PublicView.tsx` | Landing: hero → verify panel → "how it works"; live stats (`signed_docs`, `trusted_issuers`) polled every 90 s | Hero copy *"The time to doubt is **before** you forward"* states the mission in one line; polling keeps numbers alive on a projector screen. |

### 6.2 The verify machinery

| File | What it does | Why |
|---|---|---|
| `components/ui.tsx` | 24 inline SVG icons + `Button`, `Pill`, `Card`, `Field`, `Modal`, `CountUp`, `EmptyNote`, `useGsiReady`, and — critically — **`Dropzone`** | The dropzone is a **real `<label>` wrapping a visually-hidden real `<input type="file">`**. Native activation means the *browser* opens the picker, so uploads always work even when Explain mode's capture-phase click interceptor is running (see §8). Zero image assets — all icons are inline SVG — keeps the single-file build tiny. |
| `components/VerifyPanel.tsx` | File/text tabs; stages files; computes the SHA-256 **in the browser**; large files (>3.5 MB) send a 2 MB sample + full hash in one trip | The "Files stay in your browser" promise is literal — only a digest travels. One round-trip keeps big-file verify near-instant. |
| `components/VerdictCard.tsx` | Renders one verdict: stamp, reasons, AI explainer, signer block, tx/anchor, media preview, "Compare a copy", CTA row. Exports `expandZip` (unzips batches with **JSZip** and verifies each member) | Every element maps to a data field returned by `/api/verify` — nothing mocked. Media previews create an object URL **revoked on unmount** (no memory leaks on a long demo). |
| `components/NoticeBoard.tsx` | Right-rail live feed of broadcast notices; **"View archive" expands the feed inline** (scrollable) with "Show recent only" to collapse; retract own notices; `Verify digest` re-checks any entry | Inline expand instead of a modal — fewer z-index battles, one less layer of complexity, and it demos well on a fixed screen. |

### 6.3 The authority console

| File | What it does | Why |
|---|---|---|
| `components/Charts.tsx` | Dependency-free **SVG** `BarChart` / `HBarChart` | No chart library (Chart.js/Recharts would add ~100 kB to a 388 kB single file). Honest, accessible SVG with real `<img alt>` labels. |
| `components/NetworkMap.tsx` | Hand-laid **SVG** authority↔file dependency graph (fixed rows, ~26-char label truncation) | Real network graphs (vis.js, d3-force) need heavy libs and jitter badly on re-render. A deterministic hand-laid grid never moves — great for screenshots and stable demos. |
| `views/AuthorityView.tsx` | The signed-in console: Google SSO gate, sign panel (batched/chunked), broadcast composer, identity directory, ledger table+map, super-admin bar (sync / rollback / D-Day), screening desk. Rollback input converts **local → UTC** before sending | One view per persona. Local→UTC conversion prevents the classic "rollback wrong date by timezone" demo bug. Imports everything from the single typed `api.ts`. |
| `views/AnalyticsView.tsx` | Aggregate-only telemetry: session / local / global scopes; verdict mix bars; today's AI-detector usage | Course honesty: the dashboard deliberately shows **only summaries** — the ledger is public but personal records never surface. |

### 6.4 App infrastructure

| File | What it does | Why |
|---|---|---|
| `api.ts` | The **single typed fetch client**. One `request<T>()` normalizes `{ok, data, error, response}`; every endpoint is a named function | One place to add credentials (`credentials: "include"` for session cookies), non-2xx handling, stream detection. The backend contract lives here as TypeScript types — front and back can never drift silently. |
| `app/state.tsx` | `AuthProvider` (session) + `ToastProvider` (toasts, max 5 stacked, 3.8 s auto-dismiss, `aria-live=polite`) | Toast *policy* is centralized: stack cap + timeout + screen-reader announcement, no ad-hoc alert()s. |
| `app/util.ts` | `sha256Hex` (Web Crypto), `copyText`, `downloadBlob`, `shortHash` ("fdeab9ac…1108"), `parseUtc`, `formatCount`, `timeLabel`, `urgencyMeta`, `initials`, `norm` | Pure functions = unit-testable and shared across views. `shortHash` is the human-friendly fingerprint shown everywhere. |
| `app/theme.ts` | Light/dark via `useTheme`, persisted in `localStorage("nocap-theme")`, OS-aware default, applied on `<html>` **before first paint** (inline script in `index.html`) | No light-flash on load; theme survives refresh; matches OS preference until the user overrides. |
| `app/motion.tsx` | `useGlobalReveals` — IntersectionObserver scroll reveals (`.rv` → `.rv--in`), re-scan on DOM changes | Reveals are **progressive enhancement**: content is only hidden when JS (`.fx` on `<body>`) declared itself capable — if JS fails, nothing is mysteriously invisible. |
| `app/explain.tsx` | **Explain mode** — see §8. |
| `components/ProjectChatbot.tsx` | Floating `?` guide: **auto-invites after 26 s**, answers fully offline from `knowledge.ts` (token-scored search, markdown-lite rendering) | A demo judges can *play with* instead of watching. No network = no failure mode on stage. Excluded from Explain-mode interception so the two helpers never fight over a click. |
| `knowledge.ts` | ~19 curated Q&A entries + `searchKnowledge` / `answerFor` | Written in the project's own words (the "three layers" answer explains digest → signature → chain). |
| `styles.css` | The whole design system — see §7. |

---

## 7. The design system — `styles.css`

One minified file, but the tokens at the top tell the whole story:

- **Palette:** `--paper` (warm off-white), `--card`, `--night`, `--ink` greys, a **seal
  green** for the "official" identity (`--seal`), `--danger` red, `--warn` amber,
  `--slate` blue-grey. Dark theme swaps every token under `[data-theme="dark"]`.
- **Type:** `Fraunces` (humanist serif headings), `Inter` (body), `IBM Plex Mono` (digests
  and hashes — mono makes fingerprints feel cryptographic).
- **Fixed radii, shadows, ease** curves so every card feels the same.
- Border-tint system (`--border-seal*`, `--border-danger*`) tints card borders by verdict —
  ECDSA trust = green, fraud = red, without shouting.

Why tokens instead of hard-coded colors? One knob (`--seal`) updates the entire brand, and
the dark theme is literally the same file with overridden variables.

---

## 8. Explain mode — the hardest part of the frontend to get right

Explain mode turns any clickable element on screen into a "what is this?" tooltip:

- The toggler is `.ex-toggle` (`data-explain-toggle`), state persisted in
  `localStorage("nocap-explain")`, mirrored as `data-explain-mode="1"` on `<html>`.
- While on, a **capture-phase** `click` listener on `document` runs *before* the target;
  matched text → tooltip (`.explain-tip`, 292 px wide, z-index 260) from `EXPLAIN_MAP`
  keyed by normalized visible text (e.g. "verify", "authority").
- **ESC** closes the tooltip *and* turns explain off — the exit is impossible to miss.
- **Skip rules:** explains nothing over `.explain-tip`, `.guide-bot`, the toggle itself,
  or — vitally — **file pickers**: `input[type=file]` or a `<label>` wrapping one is never
  intercepted, because interception would break the native file dialog (§6.2 dropzone
  contract). This skip was the subtle bug we hunted in browser tests.

### The explain-mode contract (easy to break, protected by browser tests)
- Explain is a capture-phase `document` click listener while `data-explain-mode="1"`.
- Skip rules above are a **literal** match, and must keep matching real elements.
- Tooltips must not outlive mode-off; ESC listener binds only while a tip is showing.
- The toggle and the chatbot FAB must remain clickable in both modes.

---

## 9. Tests — 32 passing (`tests/`), all meaningful

- `test_detectors.py` — hash/signature helpers, trap inject+extract round-trips, all three
  AI backends (incl. document-aware routing), and the **5-branch decision matrix**.
- `test_screening.py` — Verhoeff + ICAO checksum validators (vector-tested), masked-field
  privacy, hash-only watchlist matching, risk scoring, adjudication flow.

Run: `python -m pytest tests/ -q` from the repo root. The tests are the *proof* layer:
they assert the security properties (privacy, tamper-evidence, decision order) that the
demo claims, so the claims are checkable, not just told.

---

## 10. Build & deploy story

- **Local run:** `START.bat` (or `cd app && python -m uvicorn main:app --port 8000`).
  The built frontend already sits at `app/static/index.html`, so FastAPI serves the whole
  site itself.
- **Frontend change:** edit under `frontend/src/`, run `npm run build` →
  `tsc --noEmit && vite build` (vite-plugin-singlefile) → regenerates `app/static/index.html`.
- **Dev loop:** `npm run dev` in `frontend/`; Vite proxies `/api → http://localhost:8000`
  (overridable with `VITE_PROXY_TARGET`).
- **Vercel:** `api/index.py` imports `app.main.app`; `vercel.json` rewrites every path to
  the one function. The ~4.4 MB multipart cap is handled by chunked uploads (§2.2).
- **Rail outs:** `main.py` (root) is a shim: `from app.main import app` — single import,
  no duplicated code.

---

## 11. File-by-file index (quick reference)

```
app/main.py             EVERYTHING backend: boot, models, vault, crypto, forensics,
                        routes, decision matrix, AI detection, blockchain, authz
app/screening.py        MHA document-screening pipeline (extract→verify→assess)
tests/test_detectors.py Core crypto/forensics/AI/matrix tests
tests/test_screening.py Checksum privacy risk-scoring tests
main.py                 Vercel/local shim → app.main.app
api/index.py            Vercel serverless entrypoint
vercel.json             Rewrites all paths to the single function
requirements.txt        Backend dependencies (FastAPI, SQLAlchemy, slowapi, …)
frontend/
  index.html            Root HTML: GSI script, fonts, pre-paint theme script
  vite.config.ts        vite-plugin-singlefile build → ../app/static/
  package.json          React 18 + TS 5 + Vite 6 + JSZip
  src/main.tsx          Entry: provider order
  src/App.tsx           Shell, nav, TopBar, Explain toggle, theme, chatbot
  src/styles.css        The whole design system (tokens) in one file
  src/api.ts            Typed fetch client — every endpoint, one shape
  src/knowledge.ts      Chatbot brain (offline search)
  src/views/PublicView.tsx     Landing + verify + notices
  src/views/AuthorityView.tsx  Sign/broadcast/ledger/screening console
  src/views/AnalyticsView.tsx  Aggregate telemetry
  src/views/gsi.ts             Google One Tap helper
  src/components/ui.tsx        Primitives + 24 icons + Dropzone
  src/components/VerifyPanel.tsx   Browser-side hash + upload
  src/components/VerdictCard.tsx   Stamp/reasons/AI/tx + expandZip
  src/components/NoticeBoard.tsx   Live feed + inline archive
  src/components/ProjectChatbot.tsx  Guided Q&A FAB
  src/components/Charts.tsx         Dependency-free SVG charts
  src/components/NetworkMap.tsx     Deterministic SVG graph
  src/app/state.tsx     Auth + Toast contexts
  src/app/util.ts       Hash/copy/download/format helpers
  src/app/theme.ts      Light/dark with persistence
  src/app/motion.tsx    Scroll reveals (progressive enhancement)
  src/app/explain.tsx   Explain-mode tooltips + interception
app/static/index.html   GENERATED single-file bundle (never hand-edit)
START.bat               One-click local launch
```

---

## 12. Why this whole design beats the obvious alternatives

| Concern | Naive alternative | Why nocap wins |
|---|---|---|
| Prove a file is official | Trust the website's word / user uploads the original | Bytes are hashed **in the browser**; only the digest travels; the ECDSA signature is checked on *re-derivation*, so even the demo user can't fake a result |
| Make forgery visible | Compare visually | The **trap** makes a *structural* tell: edited copies keep our watermark but fail the digest — forgery becomes a deterministic verdict, not an opinion |
| Keep privacy | Store files for re-check | Zero storage: SHA-256 + masked identifiers only; sessions are stateless HMAC cookies |
| Cloud AI quota / offline demo | Hard-depend on one vendor | `DETECTION_PROVIDER` switch: offline heuristic ←→ Sightengine ←→ ONNX, same verdict shape, **fails open** on quota |
| Demo stability | Fancy animation/vis libraries | Deterministic SVG charts/map, JS-safe reveals, single-file build — nothing to reload, nothing to hang |
| Explainability to judges | Walls of logs | Explain mode answers "what is this?" for *every* UI element, in the project's own words |
```