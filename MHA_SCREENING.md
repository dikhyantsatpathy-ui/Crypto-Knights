# MHA Screening — "AI-Based Fake Identity & Document Screening System"

**Problem statement:** SIH 2026 · PS **SIH26188** · Ministry of Home Affairs

> How AI, OCR, Computer Vision, and intelligent risk analysis can work
> together to detect potentially fraudulent identity documents and suspicious
> inconsistencies — *not* a black-box "valid / invalid", but **reliable,
> explainable, scalable** screening that **supports human decision-making**.

nocap already ran a provenance ledger + AI-content forensics. The upgrade turns
it into a full **screening desk** for that exact statement.

---

## How we mapped the statement onto nocap

| Statement element | What we built |
| --- | --- |
| **Upload** | `POST /api/screen` — officers upload a PDF/photo of the identity document. |
| **Extract** | Deterministic field extraction — Aadhaar, PAN, passport/MRZ, driving licence, phone, DOB — from PDF text (pypdf) and officer-declared fields. |
| **Analyze** | Checksum + format validation (Verhoeff for Aadhaar, ICAO 9303 MRZ check digits, PAN/DL structure), AI-synthetic-image scan (existing detector), scanned-document awareness, date/expiry consistency. |
| **Verify** | Cross-reference against the **nocap provenance ledger** (authentic / revoked / unknown) and a **hash-only watchlist**. |
| **Assess Risk** | Explainable risk score 0–100 → **CLEAR / REVIEW / FLAGGED**, every point carrying a human-readable reason + confidence. |
| **Human decision** | Supervisory adjudication queue — Clear / Confirm fraud / Inconclusive — recorded on the immutable report (human-in-the-loop over the AI). |

## Design principles that match the statement

- **Explainable.** There is no black box. Each risk point is a sentence
  ("Aadhaar fails the Verhoeff checksum — the number is not genuine",
  "Passport MRZ check digits FAIL — a very strong tamper signal").
- **Zero-storage.** Raw bytes *and* extracted text are never stored — only the
  SHA-256 of the file, **masked** identifiers (••••1234), and signals. The
  watchlist stores only hashes, so the desk can't leak numbers.
- **Audited.** Every run is an immutable `ScreeningReport` (screener, check
  point, verdict, signals, adjudication) — a paper trail for entry points.
- **Provenance tie-in.** If the exact document was already signed on the
  ledger, screening *rewards* that (risk −38) — the same file, one trust chain.
- **Fail-closed.** With no machine-readable evidence, the system refuses to
  clear: verdict is forced to REVIEW with a "manual inspection advised" note.

## API surface (all behind the officer session; adjudication + watchlist are super-admin only)

```
POST /api/screen                          run a screening pass
GET  /api/screen/queue                    pending adjudications + recent (scoped)
GET  /api/screen/reports/{id}             full report (signals, AI snapshot, hash)
POST /api/screen/reports/{id}/adjudicate  CLEARED | CONFIRMED_FRAUD | INCONCLUSIVE
GET  /api/screen/watchlist                (super) hash-only watchlist
POST /api/screen/watchlist/add            (super) add hashed identifier + reason
POST /api/screen/watchlist/remove         (super) remove entry
```

Verdict thresholds: risk ≤ 30 **CLEAR** · 31–62 **REVIEW** · > 62 **FLAGGED**.

## Access model

- Any **approved officer** (an identity with a super-admin-assigned post &
  institution, not revoked) may upload documents and read their own sweep of
  the queue. This keeps the desk usable for line officers while the two
  supervisory powers stay super-admin-only: **adjudication** and the
  **watchlist**.
- A pending/role-less account gets a 403 with a "role pending" reason — the
  same anti-impersonation rule as signing: the desk never lets a non-approved
  identity inject documents into the audit trail.

## Hardening added after the security review (kept green by the test suite)

1. **Stateless / UN passports.** MRZ nationality is `[A-Z<]{3}`, so `<<<` in
   the nationality field (UK/US stateless passports, UN laissez-passer) parses
   and validates instead of returning an empty result.
   (`tests/test_screening.py::test_extract_mrz_stateless_nationality`)

2. **DOB vs first-date bug.** The engine picked the *first* date on the page
   as the date of birth; a document that prints "VALID TILL" before the DOB
   falsely flagged a **DOB in the future (+30)**. It now selects the oldest
   past date — the DOB is always the oldest date on an identity card — and
   falls back to the first date so a genuine all-future scan still flags.
   (`tests/test_screening.py::test_extract_fields_dob_ignores_future_expiry`)

3. **API field contract.** The screening endpoint returned `extracted_fields`
   while the desk UI read `masked_fields` — the extracted identifiers never
   rendered. The contract is now `masked_fields` end-to-end (screen report +
   persisted `ScreeningReport` row), matching `api.ts` `ScreenReport`.

4. **Strict hash validation.** Screening and verification accept a
   `client_hash` only when it is exactly 64 hex characters — a loose
   `{1,128}` regex allowed nonsense hashes to skew ledger/write evals.

5. **Bounds & lifecycle.** Notice-attachment uploads are capped (4 MB text
   vs the previous "max 3MB" mismatch), notice text is length-capped (5000),
   `.svg` was removed from allowed signed media (an SVG can smuggle script),
   upload-session buffers are sweeped after 2 h, and the verify session cap
   (64 MB sum) keeps public chunk storage bounded.

## Run & test

```bash
python -m pytest tests/ -q                 # 32 tests — screening has 19+
cd frontend && npm run build && node smoke/run.mjs
```

## Ideas we skipped (deliberately) — and where to take them next

1. **Heavy OCR (Tesseract / PaddleOCR / DocTR).** We validated identifiers via
   checksums instead, because OCR adds weight and a Vercel function payload
   limit. Roadmap: swap `extract_fields` internals for a real OCR engine behind
   the same contract — the checksum validation layer already handles its noise.
2. **Face-match on the photo** (is the portrait the same as in the biometric
   DB?). Needs a live National/UIDAI-style API or an enrolled corpus — out of
   scope for a self-contained desk, but the document image scan is the seam.
3. **Live FRRO/Immigration integration.** The `checkpoint` field is the hook;
   a deployment collects checkpoints into a National register.
4. **What counts as *evidence*.** Today the confidence mixes signals and
   declared fields; with more reference data each signal could get a calibrated
   weight. The table lives in `app/screening.py` so it is tunable without
   touching the API contract.