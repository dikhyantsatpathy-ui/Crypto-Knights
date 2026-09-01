# Crypto-Knights — SIH 2025 Presentation (Corrected)

**Event:** Smart India Hackathon 2025
**Problem Statement ID:** S26
**Title:** Deepfake-Resistant Provenance and Verification System for Official Digital Communications
**Theme:** Blockchain & Cybersecurity · **PS Category:** Software
**Team ID:** Crypto-Knights
**Product name:** **No Cap**
**Tech:** ECDSA SECP256R1 · AES-256-GCM KMS vault · FastAPI · PostgreSQL · IPFS/Pinata

> This deck is corrected against the actual codebase (`app.py`, `main.js`, `index.html`).
> Removed: PQC migration content, Dart/Flutter app, TensorFlow/ML, Twilio SMS, Google Translate — none of these exist in the implementation.

---

## Slide 1 — Title
**No Cap**
Deepfake-Resistant Provenance & Verification System for Official Digital Communications
*Team Crypto-Knights · SIH 2025 · PS ID S26 · Blockchain & Cybersecurity*

---

## Slide 2 — The Problem
- Deepfake audio, cloned voices, photoshopped PDFs, and forged "official" notices are flooding the internet.
- Institutions can't **prove** a document is genuinely theirs.
- Citizens can't **independently verify** what they received.
- Existing defenses fail:
  - **Watermarks** → photoshopped away in seconds.
  - **Single-server databases** → silently rewritable by an insider/attacker.

**Gap:** nobody can *cryptographically* prove official-ness without trusting the issuer.

---

## Slide 3 — Our Solution (One-liner)
**No Cap** cryptographically signs official audio/video/PDF/text, anchors a tamper-evident receipt on **IPFS + an EVM Layer-2**, and gives the public an **open verifier** that classifies any file as:
**AUTHENTIC ✔ · PROVEN FAKE ⚠ · REVOKED · UNSIGNED**
— warning, not a generic "Invalid".

---

## Slide 4 — System Architecture: Signing Pipeline
```
INSTITUTIONAL AUTHORITY (Admin)
   │  Google OAuth SSO → HttpOnly cookie (nischay_session)
   ▼
CLIENT ENGINE (main.js)
   • hashes the file at the edge (SHA-256, in memory)
   • sends only HASH + institution ID   (raw media / raw keys never transmitted)
   ▼
ZERO-TRUST BACKEND (app.py)
   • KMS VAULT (AES-256-GCM)  → private key decrypted IN RAM only
   • ECDSA SECP256R1 signing  → signature created, key purged from memory
   • Media trap injected       → hidden crypto metadata written into the file's
                                 native container (PDF metadata / MP3 ID3 / MP4
                                 atom) via PyPDF + mutagen
   • Optional anchor           → IPFS (Pinata) + EVM L2 (blockchain)
   ▼
POSTGRES LEDGER (SQLAlchemy)  ← stores hash, sig, CID, merkle root
```

---

## Slide 5 — System Architecture: Verification Pipeline
```
PUBLIC CITIZEN
   │  uploads received file → Public Verification Portal (index.html)
   ▼
CLIENT ENGINE (main.js)
   • recomputes SHA-256 hash at the edge
   ▼
BACKEND VERIFIER (app.py)
   • queries the ledger (SQLAlchemy)
   • checks embedded metadata (media trap)
   • validates the ECDSA signature against the stored issuer pubkey
   ▼
ENTERPRISE REGISTRY
   • PostgreSQL DB (Neon)  +  IPFS network via Pinata (CID reference)
   ▼
VISUAL FORENSICS ENGINE (Vis.js)
   verdict banner + ledger graph:
   AUTHENTIC · PROVEN FAKE · REVOKED · UNSIGNED
```

---

## Slide 6 — Cryptography & Trust (Zero-Trust)
- **ECDSA SECP256R1** per **NIST FIPS 186-4** — the same curve class used for NSA-grade signing.
- Private keys are **never on the user's machine**. They live encrypted in a **server-side AES-256-GCM KMS vault**, decrypted into RAM only for the signing instant, then purged (`HKDF` per-owner key, `app.py:245`).
- A signature therefore **cannot be forged remotely** — an attacker would have to physically steal the decryption key.
- **Media trap:** we inject hidden cryptographic metadata into the file's own
  container — PDF metadata keys, MP3 ID3 frames, MP4 comment atoms — via PyPDF
  + mutagen. A visible watermark is easy to photoshop; this hidden in-container
  proof is not. If anyone edits the file, the trap breaks → verifier reports
  "FORENSIC TRAP TRIGGERED — DEEPFAKE".
- **Immutable revocation (kill switch):** one DB flag instantly revokes every block for that institution (`/api/revoke`) while preserving the full, verifiable history.

---

## Slide 7 — Tech Stack
| Layer | Technology |
|-------|-----------|
| Backend | Python 3.9+, FastAPI (async), SQLAlchemy ORM |
| Cryptography | ECDSA SECP256R1 (FIPS 186-4), AES-256-GCM vault, HKDF |
| Database | PostgreSQL (Neon cloud; SQLite locally) |
| Distributed storage | IPFS via Pinata (CID anchored receipts) |
| Blockchain | EVM Layer-2 (optional Web3 anchoring, simulated by default) |
| Client | JavaScript (edge SHA-256 hashing, notice board, verifier) |
| Media / docs | PyPDF, mutagen |
| Visualization | Vis.js (ledger dependency graph + verdict UI) |

---

## Slide 8 — Feasibility
- **Technical:** FastAPI + SQLAlchemy scale from SQLite to Neon PostgreSQL clusters. Heavy media is hashed **client-side** so the server never times out on big uploads.
- **Operational:** sensitive files **never touch the hard drive** — processed entirely in RAM via `io.BytesIO()`; private keys never leave the encrypted vault.
- **Economic:** 100% open-source libraries (PyPDF, mutagen); **Pinata IPFS** instead of costly centralized AWS S3.
- **Zero-config demo:** with no `WEB3_RPC_URL` / `PINATA_JWT`, the engine degrades gracefully to **simulated** CIDs/tx — the full flow works without external services.

---

## Slide 9 — Challenges & Solutions (in code)
| Challenge | Solution Implemented |
|-----------|----------------------|
| DB connection leaks crashing the server | `@contextmanager` forces every DB connection to close safely on success *or* failure |
| Watermark forgery (photoshopping) | Hidden cryptographic **metadata traps** injected into the file container (PDF metadata / MP3 ID3 / MP4 atoms) — any edit breaks the trap |
| Centralized single point of failure | Hashes anchored to **decentralized IPFS** → immutable + highly available |
| Emergency notices being forged/edited | Public **Emergency Board** (public read API) shows last-24h notices; only original issuer may resurrect a retracted notice (prevents signature corruption) |
| Email privacy | Board API never returns emails; `can_delete` only via valid session cookie |

---

## Slide 10 — Impact & Benefits
**Zero-Trust threat intelligence**
- Not a generic "Invalid" — actionable forensics via 4 classification states.

**Immutable revocation**
- Instant DB flag revokes trust across all blocks for a compromised institution; the historical audit trail stays intact and verifiable.

**Enterprise-grade security**
- Signatures can only be forged if the ECDSA vault key is physically stolen — the server never ships keys to clients.

**Speed** — SECP256R1 curves are small & fast vs RSA.
**Reliability** — SQLAlchemy ORM neutralizes SQL-injection and brittle queries.
**Concurrency** — FastAPI's native async keeps the server responsive during batch uploads.

---

## Slide 11 — Demo Flow (short)
1. Authority logs in via **Google OAuth** (admin approved by super-admin).
2. Authority signs an **Emergency Broadcast** (or uploads a PDF/audio/video).
3. Receipt anchored: ledger row + optional IPFS CID.
4. Public visitor opens the **Public Verification Portal**:
   - Pastes text / uploads file → gets **AUTHENTIC / PROVEN FAKE / REVOKED / UNSIGNED**.
5. Compromised signer? **Revoke** with one click → all their blocks flip to REVOKED.

---

## Slide 12 — Research & References
- [1] Institute of Technical Education & Research (ITER), SOA University — *VeriSource: Enterprise Provenance Engine Technical Documentation & Architecture Guide.*
- [2] NIST, *FIPS 186-4: Elliptic Curve Digital Signature Algorithm (ECDSA) SECP256R1 Standards.*
- [3] Protocol Labs, *InterPlanetary File System (IPFS) Decentralized Anchoring Architecture.* https://ipfs.tech/
- [4] Pinata, *IPFS Network API Documentation for Web3 Infrastructure.*

---

## Appendix — Where the original PDF was wrong (fixed here)
1. **Removed** the "Discovery & mapping / Risk assessment / Phased migration" PQC block — that describes a *post-quantum crypto migration product*, **not** this system.
2. **Removed** Dart (Flutter app), TensorFlow/ML, Twilio SMS, Google Translate — **not in the code** (`requirements.txt` has none of these).
3. **Fixed the "visual QR / ReportLab" claim** — the code embeds hidden metadata into the file container (PDF metadata via PyPDF, MP3/MP4 via mutagen). There is no QR-code rendering and no ReportLab dependency in the implementation.
4. **Fixed key-location claim:** keys are in the **server-side AES-256-GCM KMS vault**, NOT "physically on the user's local machine."
5. **Fixed** "admin uploads ZIP as required input" → signing is single file / text notice; ZIP is only an optional **download** format for signed batches.
6. **Clarified** IPFS/Pinata and EVM L2 are **optional** (simulated when env blank), not mandatory.
6. **Clarified** crypto is **ECDSA SECP256R1** (not RSA); RSA only referenced as a "slower alternative" comparison.
