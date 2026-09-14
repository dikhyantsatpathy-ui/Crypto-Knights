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