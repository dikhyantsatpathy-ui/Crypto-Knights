# Hashing, Lock-Keys & the AI Model — the complete explanation

Everything below is verified against the code (`app/main.py`, `app/screening.py`,
`app/identity.py`, `scripts/train_vit_onnx.py`). File:line references included so
you can check any claim in seconds.

---

## PART 1 — What is hashed, and why

Every hash in the system is **SHA-256**. There are no passwords stored anywhere
(no login passwords exist at all — sign-in is Google OAuth), so there is no
password-hashing; hashing here is used for **identity, lookup, and integrity**.

### 1.1 File hashes — the backbone of the whole ledger

| Step | Code | What is hashed |
|---|---|---|
| Sign: raw hash | `main.py:2245` `raw_hash = sha256(raw)` | the exact bytes the officer uploaded |
| Sign: trap + final hash | `main.py:2248` `final_hash = sha256(trapped)` | the bytes AFTER the forensic trap is injected |
| Ledger row key | `blocks.file_hash` (UNIQUE) | the **final** (trapped) hash — this is what verification looks up |
| Verify: target | `main.py:2429/2472/2515` | recomputed bytes hash, or the `client_hash` the browser attests |
| Re-sign dedup | `insert_block_once` | same bytes → same hash → UNIQUE constraint makes it a no-op |
| Tamper trip-wire | `main.py:2586` | recomputed hash ≠ ledger hash ⇒ content changed after signing |
| Broadcast text | `main.py:2143` | message bytes (+ media bytes) = the signed artifact |
| Broadcast media | `main.py:2169` | attached image/video bytes, recorded in the receipt |
| IPFS receipt id | `main.py:1264` (simulated mode) | canonical JSON of the receipt |

Why two hashes at sign time (`raw_hash` then `final_hash`)? The trap injector
embeds the signature *inside* the file, which changes its bytes. The ledger
must record the hash of what actually ships (`final_hash`); the first signature
covers the original so the trap itself is authenticated. A verifier recomputes
the hash of the file in hand and looks it up — match means "this exact file was
signed", mismatch means "forgery or different file". No file bytes are ever
stored: the database holds digests, the file lives with its owner.

### 1.2 Identifier hashes — zero-storage identity

| What | Code | Rule |
|---|---|---|
| Watchlist entries | `screening.py:53` + `main.py:3221` | `sha256(norm(value))` — normalized (case/punctuation collapsed) then hashed |
| Aadhaar/PAN/DL names & numbers | `identity.py` (`sha256(...)[:32]`) | 32-hex-char truncated digests, masked tails only on screen |
| Screening extracted fields | `run_screening` audit row | masked JSON + hashes, never raw text |

Consequence: a database leak reveals **no** Aadhaar numbers, names, or document
text — only one-way digests. Name *matching* still works because both sides
hash the same normalized value and compare digests.

### 1.3 Merkle + chain anchoring

`compute_merkle_root` (`main.py:1915-1919`): leaves are file hashes, paired and
re-hashed up the tree (`sha256(left + right)`), `sha256(b"GENESIS")` when empty.
The root is anchored on-chain (`anchor_merkle_to_chain`); with no Web3
credentials configured it returns a clearly-labeled `0xSIMULATED_TX_<hash>`
instead of pretending to be on-chain.

### 1.4 Session HMAC (not a password hash — a signature)

Covered in Part 2 below. Same SHA-256 core, different job: proving a cookie was
minted by this server.

---

## PART 2 — The "lock key thing" (KMS vault + sessions)

There are two key systems. They share one master secret but do different jobs.

### 2.1 The master key

```
MASTER_VAULT_KEY=<32+ random bytes>   # in .env, NEVER committed
```

- The app **refuses to boot** without it (`main.py:879`), and Google OAuth
  client ID is equally mandatory. Both are deployment secrets, not code.
- **Changing it later breaks signing for every existing identity** (their
  stored private keys become undecryptable). This is warned at startup and in
  `.env.example` — treat it like a safe combination: set once, back up
  offline, never rotate casually.

### 2.2 Per-officer lock-box (the actual "lock key")

Each officer owns one ECDSA P-256 signing key. The **private half is locked**;
the public half is stored in the clear (public keys are meant to be public).

```
owner_key = HKDF-SHA256(master = MASTER_VAULT_KEY,
                        salt   = lowercase(officer_email),
                        info   = "nischay-owner-vault-key-v1")   # 32 bytes
stored    = base64(nonce_12B || AES-256-GCM(owner_key, private_PEM))
```

Code: `derive_owner_key` (`main.py:1187`), `encrypt_vault_key` (`1191`),
`decrypt_vault_key` (`1197`).

Read it as nested locks:

1. **Master lock** — `MASTER_VAULT_KEY` opens everything (server-side only).
2. **Owner lock** — HKDF mixes the master with the officer's email, so every
   officer gets a *different* AES key. Officer A's locked box cannot be opened
   with Officer B's derived key, even though one master underlies both.
3. **Fresh nonce per lock** — `os.urandom(12)` each time, so locking the same
   key twice produces different ciphertext (no pattern leaks).
4. **Tamper-evident seal** — AES-GCM authenticates: a edited ciphertext fails
   decryption instead of decrypting to garbage.

Limit is honest: anyone holding `MASTER_VAULT_KEY` **and** the database can
derive every owner key. That is by design (server-side KMS, not end-to-end
encryption) — the threat model is *database leak without the env secret* and
*officer isolation*, both of which hold.

### 2.3 The signing moment (when the box is opened)

`load_active_signer` (`main.py:2068`) — every `/api/sign*` call passes through it:

1. Look up the caller by email; reject if unknown or `is_revoked`.
2. Reject if a super admin hasn't approved their institution + designation
   (no self-typed titles can sign).
3. `decrypt_vault_key(enc_priv_key, email)` → private key lives **only in
   memory, only for this request** — it is never written to disk, logs, or DB.
4. Sign `raw_hash`, inject trap, sign `final_hash`, store the ledger block.

### 2.4 The session cookie (how the browser proves "it's me")

No server-side session table exists. After Google OAuth passes the
domain/email gate, the server mints a self-contained token
(`make_session_token`, `main.py:1203`):

```
token = email :: expiry_unix (+24h) :: HMAC-SHA256(MASTER_VAULT_KEY, "email::expiry")
cookie: nischay_session, HttpOnly, Secure on Vercel, SameSite=Lax, 24h max-age
```

Every protected route runs `get_current_admin` (`main.py:1215`): re-split the
three parts, recompute the HMAC with `hmac.compare_digest` (timing-safe), and
reject on mismatch **or** expiry. Forging a cookie needs the master key;
replay dies after 24h; there is nothing server-side to steal or clean up.

The public broadcast feed uses a lighter peep-hole, `_viewer_from_cookies`
(`main.py:2741`): same HMAC check, no expiry enforcement, purely to decide
whether to show an author their own per-row delete buttons. (Fixed this turn:
it used to return `"email::exp"` as the identity, so the owner comparison never
matched — see `tests/test_auth.py`.)

### 2.5 Signatures on files (ECDSA, not HMAC)

File signatures are ECDSA over P-256 (`hybrid:<hex>` prefix): the officer's
private key signs the file hash; anyone with the officer's *public* key
(`signer_identities.pub_key`, stored plaintext) can verify. HMAC is only for
cookies (shared-secret setting); ECDSA is for files (public-verifiability
setting). Different tools because the trust direction is different.

---

## PART 3 — The AI model I just created (trainer + runtime)

### 3.1 What exists right now (no action needed)

Out of the box, the app does **not** need your training or any files from you:

- Runtime default model: `onnx-community/ai-image-detection-ONNX` — a ViT-Base
  already fine-tuned on CIFAFE (real vs AI-generated). On first use the loader
  (`_ensure_model`, `main.py:595`) downloads it into `data/models/` and caches
  it. Set `AI_DETECTOR_PROVIDER=self-hosted` and it just works.
- What I "created" is a **replacement pipeline**: `scripts/train_vit_onnx.py`
  (local helper, intentionally not committed — `scripts/` is gitignored by repo
  convention) + the `TRAINING.md` runbook. It exists so you can train *your
  own* weights later. Nothing about the running app depends on it today.

### 3.2 How the trainer works, step by step

```
python scripts/train_vit_onnx.py --data-dir data/datasets/fake-detector \
    --epochs 3 --batch-size 32 --lr 3e-5 --device cuda
```

1. **Reads the dataset** — `data/datasets/fake-detector/{train,val}/{real,fake}/`.
   The folder tree IS the database (no SQL involved); class order is fixed
   `[real, fake]` because the runtime reads the logits in that order.
2. **Preprocesses exactly like the runtime**: resize to 224×224, pixels ÷255,
   **no mean/std normalization**. This is the #1 correctness rule — the
   deployed graph only understands 0–1 inputs, so training on normalized
   inputs would silently destroy accuracy.
3. **Model**: `torchvision` ViT-Base (`vit_b_16`, ImageNet-1K V2 weights, 86M
   params) with its 1000-class head swapped for a fresh 2-neuron head
   (`real` vs `fake`). Fine-tuning (AdamW, lr 3e-5, ~3 epochs) teaches the
   head the fake-image fingerprints while keeping the backbone's vision.
4. **Validates each epoch** on the held-out `val/` split; saves the best
   checkpoint to `data/models/best_state.pt`.
5. **Exports ONNX** (`model.onnx`, opset 17, dynamic batch, input `input`
   `[batch,3,224,224]` fp32 → output `logits` `[batch,2]`) — the exact filename
   the runtime loader looks for, so activation needs no renaming.
6. **Smoke-tests the export** through `onnxruntime` (output shape `[1,2]`,
   softmax sums to 1) and writes `data/models/weights.json`: version, SHA-256
   of the file, class order, threshold `0.5`, val accuracy, dataset path, date.
7. **`--predict` mode** sanity-checks single images/folders against the
   exported file.

### 3.3 How the running app uses the model

`onnx_detect` (`main.py:652`): preprocess (resize 224, ÷255, channel-first) →
ONNX Runtime inference → `onnx_score` (`main.py:632`): softmax over the 2
logits, `P(fake) = probs[1]`, reported 0–100, `ai_suspected = score >= 50`.
The verdict, score, latency and raw logits ride along in every `/api/verify`
response and into the `VerificationLog` row (which is what the analytics
latency/provider graphs aggregate). If the model file or `onnxruntime` is
missing, it fails **open** with `ran: False` and the rule-based heuristics
carry the verdict — screening never hard-depends on the model.

Provider selection (`main.py:732`): `AI_DETECTOR_PROVIDER=self-hosted` forces
this path; `sightengine` uses the cloud API; unset auto-picks Sightengine when
a key exists, else heuristics. The optional YOLOv8 ROI detector
(`app/yolo_roi.py`, `app/models/yolov8n.onnx`) is a separate, also-optional
model that only draws face/document boxes — the suite degrades gracefully
without it.

### 3.4 Do you need to put in files, train, or do anything?

**No.** For the demo, judging, and deployment as it stands: nothing. Checklist:

- [ ] Nothing to download — the default model self-downloads on first use.
- [ ] Nothing to train — train only if you want *your own* weights (e.g. tuned
      to Indian ID-card fakes). Then follow `TRAINING.md` §3–§4 and set
      `AI_DETECTOR_PROVIDER=self-hosted` + `AI_DETECTOR_MODEL_DIR`.
- [ ] Dataset needed only in that case: ≥5k real + ≥5k fake images in the
      documented folder layout; keep `labels.csv` + hyperparams for audit.
- [ ] Never commit weights or datasets (`data/models/`, `data/datasets/` are
      gitignored; Vercel's 128 MB cap forbids weights in the bundle anyway —
      host them on a Release/HF and point `AI_DETECTOR_MODEL_URL` at the file).
- [ ] After any retrain: bump `weights.json` version, re-run the two-sample
      live check (one known-fake, one known-real through `/api/verify`), then
      deploy.

---

## PART 4 — The one-line mental model

**Hashes prove *what* (file identity, no raw data stored). The vault keys prove
*who may sign* (per-officer lock-boxes under one master). The session HMAC
proves *who is asking* (stateless cookie). The AI model guesses *whether pixels
were generated* (probabilistic hint, never a verdict on its own).**
