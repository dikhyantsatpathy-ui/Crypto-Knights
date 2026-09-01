# No Cap — Backend Hashing & Signing Study Guide
### The complete "I handled the hashing" script — code-cited against `app.py`

**Product:** No Cap · **Repo:** `Veri_source` · **Backend:** FastAPI (`app.py`)

> Use this to answer ANY question about hashing/signing/verification in the demo.
> Every claim is pinned to a real line in `app.py`, so you can say "here's the exact code" —
> not "trust me, it's secure."
>
> **Cheat-line for the panel:** *"At engine startup we run idempotent schema migrations; every
> artifact is hashed with SHA-256 (line 577 / 660 / 663), bound to text+media (576), signed with
> an ECDSA SECP256R1 key (592 / 661 / 664), the signature is verified with the signer's public
> key (757-758), receipts are anchored to a Merkle root (363-369) and to IPFS + an EVM Layer-2 (314-385)."*

---

## 1. THE ONE-SENTENCE MODEL

**No Cap never stores the artifact to prove it — it stores a *digest* and a *signature* over that digest, in an append-only ledger.** If any byte of the artifact changes, its digest changes, the stored signature stops matching, and verification returns **PROVEN_FAKE**. That single idea drives the whole app.

---

## 2. WHERE HASHING HAPPENS IN THE CODE (with line numbers)

| Purpose | Function | SHA-256 instantly: |
|---|---|---|
| Text/emergency notice + optional media → payload hash | `sign_text_notice` → `app.py:576-577` | text `encode()` **+ `\x00MEDIA\x00` + media bytes** |
| Authoritative signature over that hash | `_sign_text_core` → `app.py:592` | `priv.sign(text_hash, ECDSA(SHA256))` |
| Media files: pre-trap hash (kept for forensics) | `sign_media` → `app.py:660` | `sha256(raw)` |
| Media files: final hash over trapped bytes (shipped) | `sign_media` → `app.py:663` | `sha256(trapped)` |
| Receipt SHA-256 of the media bytes themselves | `app.py:603` | `sha256(media_bytes)` |
| Verify: hash the incoming file | `resolve_verify_input` → `app.py:705` | `sha256(raw)` |
| Verify: hash raw text (broadcast path) | `verify_media` → `app.py:721-723` | `sha256(raw_text.strip())` |
| Verify: signature check | `verify_media` → `app.py:754-758` | `pub.verify(sig, target_hash, ECDSA(SHA256))` |
| IPFS receipt (simulated CID) | `upload_receipt_to_ipfs` → `app.py:317` | `sha256(receipt JSON)` |
| Merkle root of all unanchored blocks | `compute_merkle_root` → `app.py:363-369` | pairwise `sha256(h1 + h2)` |
| Web3 anchor (simulated tx) | `anchor_merkle_to_chain` → `app.py:372` | `sha256(merkle_root)` → pseudo-tx |
| Session cookie tamper-proofing | `make_session_token` → `app.py:278-279` | HMAC-SHA256 email |
| Vault key encryption | `encrypt_vault_key` → `app.py:266-269` | AES-256-GCM (line 25 import) |

---

## 3. THE HASHING PIPELINE (walk through, sign → verify)

### Signing a text emergency notice
1. `clean_msg = message.strip()` — the alert text.
2. `payload = clean_msg.encode() + (b"\x00MEDIA\x00" + media if attached)` — if there's an image/video it is **bound into the hash** so a swapped image can't pass (`app.py:576`).
3. `text_hash = sha256(payload)` (`app.py:577`).
4. Sign with the signer's **ECC private key** → `"hybrid:" + ECDSA-SHA256 signature` (`app.py:592`).
5. Store `{file_hash, sig_hex, timestamp, ipfs_cid}` as a new `LedgerBlock` (`app.py:625-635`).

### Signing a media file (audio/video/PDF)
1. `raw_hash = sha256(raw bytes)` and sign it — signature #1, kept for forensic comparison (`app.py:660-661`).
2. `inject_media_trap()` embeds a hidden Nocap metadata tag into the actual container (PDF/MP3/MP4) (`app.py:325-351`).
3. `final_hash = sha256(trapped bytes)` and sign — signature #2 is the authoritative one shipped to the public (`app.py:663-664`).

### Verifying (a verifier has no keys — only the public ledger)
1. Compute `target_hash` from whatever "proof" is supplied: the file bytes, the raw text, or a client-supplied hash (`app.py:690-713`).
2. Look up `target_hash` in the `blocks` ledger (`app.py:739`).
3. If **not** in ledger → `UNSIGNED` (never seen before), or `PROVEN_FAKE` if a hidden trap is found on a file that was never ours (`app.py:740-744`).
4. If **in** ledger but the signer's key was revoked or the block revoked → `REVOKED` (`app.py:750-752`).
5. If **in** ledger → load the signer's **public key**, run `pub.verify(signature, target_hash, ECDSA-SHA256)` (`app.py:754-758`):
   - Verifies → `AUTHENTIC`.
   - Throws → `PROVEN_FAKE` ("Binary altered") (`app.py:764-765`).

---

## 4. THE 12 BUZZWORDS — TECHNICAL + LAYMAN MEANINGS

| # | Buzzword | Technical meaning (what to say) | Layman meaning (how to say it) |
|---|---|---|---|
| 1 | **SHA-256** | A one-way cryptographic hash producing a fixed 64-hex (256-bit) digest; collision-resistant (2^128 birthday bound); deterministic and avalanche-sensitive. | A digital "fingerprint" — same file always gives the same fingerprint, and changing even one pixel scrambles the whole fingerprint. You can't reverse a fingerprint into a file. |
| 2 | **Cryptographic hash** | Preimage-resistant (can't invert), collision-resistant, deterministic, non-invertible mapping of arbitrary bytes → fixed-length digest. | One-way blender: put anything in, get a fixed-size code out; nobody can work backwards from the code to the input. |
| 3 | **Avalanche effect** | Changing one input bit changes ~50% of output bits; ensures tampering is obvious. | Flip one tiny bit and the whole fingerprint looks completely different — so any tamper shouts loudly. |
| 4 | **ECDSA SECP256R1** | Elliptic Curve Digital Signature Algorithm on the NIST P-256 curve; 256-bit key ~128-bit security; sign with private key, verify with public key. | A digital signature like a wax stamp — only the owner's secret stamp can make it, but anyone can check the stamp against the owner's public seal. |
| 5 | **Public / private key pair** | Asymmetric: private keeps secret (sign), public published (verify). Nobody can derive private from public (ECDLP). | Two linked keys: one you never share (creates signatures), one you share (checks signatures). You can't work the secret back out from the public one. |
| 6 | **Merkle tree / Merkle root** | Binary hash tree; combine children pairwise with SHA-256; root commits to the entire set; a single leaf change changes the root. | A "roll-call" of hashes stacked into one top hash — if any member changes, the top hash changes, so the whole batch is tamper-evident. |
| 7 | **AES-256-GCM** | Authenticated symmetric encryption; 256-bit key; GCM = Galois/Counter mode with built-in authentication tag. | A sealed, tamper-proof lockbox — the same lock also detects if anyone forced it open. |
| 8 | **HMAC-SHA256** | Keyed hash (Message Authentication Code): `MAC = HMAC(key, message)`. Proves the message is untampered and from the key owner. | A signature made with a shared secret password, so a server can prove a cookie wasn't rewritten. |
| 9 | **IPFS / CID** | Content-addressed storage; the address is (by construction) the hash of the content; Pinata pins it. | A cloud locker whose address IS the file's fingerprint — same file ⇒ same address, stored immutably. |
| 10 | **Web3 / EVM anchor** | A Merkle root is written into an Ethereum-compatible transaction so the proof is timestamped on-chain and immutable. | We ink the "master fingerprint" into a public, unchangeable blockchain receipt for the world to check. |
| 11 | **Append-only ledger** | Ledger entries are only ever added (or marked deleted), never silently overwritten; `file_hash` is UNIQUE. | A logbook you can only add pages to, never erase one — so history can't be rewritten. |
| 12 | **Signature prefix `hybrid:`** | Format tag on the sig string; stored as `"hybrid:" + hex(sig)`, swappable for other schemes later. | A label in front of the fingerprint saying "this is the signature" so the system can tell signatures apart. |

---

## 5. PANEL Q&A — POSSIBLE QUESTIONS AND SOLID ANSWERS

### Q1. "Why SHA-256 and not MD5 or SHA-1?"
**A:** SHA-1 and MD5 have demonstrated collision attacks (SHAttered, etc.). SHA-256 offers ~128-bit collision resistance and is the standard for modern signatures. `app.py` uses `hashlib.sha256` everywhere (576/577/603/660/663/705/723). We also use ECDSA's own SHA-256 (`app.py:758`).

### Q2. "Hashes aren't encryption. What's the difference?"
**A:** Encryption is reversible (with the right key). A hash is one-way and non-invertible. We *hash* so we never expose the actual file or message, and we *sign the hash* with ECDSA (asymmetric) while we *encrypt private keys* with AES-256-GCM. Both matter: hash = integrity, signature = authenticity, AES = confidentiality.

### Q3. "How does the verifier check authenticity WITHOUT the private key?"
**A:** The private key is only used to *create* the signature. Verification uses the **public key** (stored on the signer's `SignerIdentity`, exported at registration, `app.py:297`). `pub.verify(signature, hash, ECDSA-SHA256)` at `app.py:757-758` proves the signature came from the matching private key and the hash hasn't changed. This is the whole point of public-key crypto.

### Q4. "What if an attacker re-signs a fake with their own key?"
**A:** They'd produce a signature that verifies under *their* public key — but the ledger stores the *issuer's* block with the *issuer's* public key and the original `file_hash`. If their hash doesn't match a ledger row signed by that identity, it returns `UNSIGNED` or `PROVEN_FAKE`. The public ledger is the source of truth, not the attacker's claim.

### Q5. "What exactly is the 'hybrid' prefix? Post-quantum crypto?"
**A:** No. `hybrid:` is just a **format tag** we prepend to the hex signature (`app.py:592, 661, 664`) so the parser (`app.py:755` splits on `:`) can identify the signature format. It is NOT post-quantum and NOT multi-sig. It is a versioning label. (The dual signature for media is pre-trap + post-trap bytes — see Q10.)

### Q6. "How do you detect deepfakes / tampered media?"
**A:** Three layers:
1. **Hash binding:** any byte change alters the hash and fails verification (`app.py:664` vs `app.py:705`).
2. **Hidden metadata trap:** `inject_media_trap()` embeds `NOCAP_ISSUER / NOCAP_SIG / NOCAP_TIMESTAMP` into PDF/MP3/MP4 (`app.py:325-351`); `extract_media_trap()` (`app.py:353-361`) checks for it. A trap on a file never in our ledger, or a trap whose hash doesn't match, proves manipulation → `PROVEN_FAKE` ("FORENSIC TRAP TRIGGERED") (`app.py:741-743`).
3. **Signature mismatch** → `PROVEN_FAKE` (`app.py:764`).

### Q7. "Is the Merkle root actually used?"
**A:** Yes. `compute_merkle_root()` (`app.py:363-369`) batches all unanchored blocks into one root, and `anchor_merkle_to_chain` writes that root to a simulated chain tx when Web3 is unconfigured (`app.py:372`), or a real EVM tx when `WEB3_RPC_URL` + `WALLET_PRIVATE_KEY` are set (`app.py:371-385`). Without keys it returns `0xSIMULATED_TX_<sha256 of root>`.

### Q8. "How is the session cookie prevented from forgery?"
**A:** `make_session_token()` (`app.py:278`) returns `email::HMAC-SHA256(MASTER_VAULT_KEY, email)`. `get_current_admin()` (`app.py:286-289`) recomputes the HMAC and `hmac.compare_digest` rejects tampered tokens with a constant-time comparison.

### Q9. "Where are the private keys and how are they protected?"
**A:** At registration, `get_or_create_signer_identity` generates an ECDSA SECP256R1 key and stores only the **encrypted private key** (`app.py:296-304`). `encrypt_vault_key` AES-256-GCM encrypts it with a per-owner derived key (`app.py:266-269`); `decrypt_vault_key` (272-276) unlocks it only when actually signing. Plaintext keys never touch the DB.

### Q10. "Media has TWO hashes — is that a bug?"
**A:** No — it's deliberate. `sign_media` computes:
- `raw_hash` = hash of the **original bytes** + signature #1 (`app.py:660-661`), kept for forensic comparison.
- `final_hash` = hash of the **trapped (metadata-injected)** bytes that actually ship + signature #2 (`app.py:663-664`).
Both are verifiable; the shipped block uses `final_hash`. This lets us distinguish "untouched original" from "our signed, stamped copy."

### Q11. "Can the ledger be rewritten by an insider? Isn't a DB insecure?"
**A:** Mitigations: `file_hash` is UNIQUE at the DB level (`app.py:192`), so a hash can't be silently duplicated; blocks are append-only; retraction only flips `notice_deleted` (86/91) and still keeps the original signed hash; the Merkle+Web3 root (`app.py:363-385`) is the external, tamper-evident anchor an insider can't forge without the chain.

### Q12. "Why does an untrusted gmail user NOT get in?" 
**A:** Login is gated by an allowlist: super-admin OR `ALLOWED_DOMAINS` (the Google `hd`/domain) OR `ALLOWED_EMAILS` — otherwise 401 at `admin_login` (`app.py:426-445`). And even after login, you cannot sign until a super-admin assigns your role (`load_active_signer`, `app.py:513-528`).

### Q13. "Is the hash of a text broadcast the same as an identical text someone else signs?"
**A:** Yes — hashes are deterministic. That's why the ledger protects the *first* writer: the `file_hash` is UNIQUE (`app.py:192`), so the first signer owns that content; a re-issue by the same issuer only revives a retracted notice (`app.py:611-613`), and a different key would fail verification.

### Q14. "What does the verifier output look like?"
**A:** `{verdict, message, hash, filename, signer, tx_hash, retracted, blockchain_explorer}` (`app.py:735-737`). Verdicts: `AUTHENTIC`, `PROVEN_FAKE`, `REVOKED`, `UNSIGNED`.

### Q15. "Where is the content itself stored if only hashes go in the ledger?"
**A:** For emergency notices, the content and media bytes ARE stored in the block (`notice_content`, `notice_media_data` — columns 185-189) so the public board is renderable; the hash guarantees integrity. For media files, we return the signed file and store the receipt on IPFS (`app.py:605, 314-323`). The ledger's hash is the tamper-evident anchor, not the only copy.

---

## 6. THE 30-SECOND DEMO SPIEL (memorize this)

> "Every file or notice is **hashed with SHA-256** — a fingerprint you can't reverse and can't fake. A signer **digitally signs that fingerprint** with their private ECDSA key. The signed fingerprint plus the issuer's public key go into our **append-only ledger**. The public verifier does one thing: take whatever you give it, **hash it again**, look it up, and **check the signature against the signer's public key**. If a single byte changed, the fingerprint changes, the signature breaks, and it says PROVEN_FAKE. To stop yourself from being forged as the issuer we seal private keys in an **AES-256-GCM vault**, and we lock the whole ledger to the world with a **Merkle root anchored to IPFS and an EVM blockchain**."

---

## 7. RAPID-FIRE ONE-LINERS (for the Q&A stretch)

- **"Why hashes?"** → Immutable, one-way fingerprints that make tampering obvious without storing secrets.
- **"Why ECDSA?"** → Fast, compact signatures; private signs, public verifies; standard and well-supported.
- **"Why AES-GCM?"** → Authenticated encryption: confidentiality + integrity in one primitive.
- **"Why Merkle+chain?"** → It turns a private database into a publicly anchored, tamper-evident ledger.
- **"Why allowlist login?"** → So a forged Google account can't even get in, and new users are onboarded by domain/email, not code.
- **"Deterministic?"** → Same input ⇒ same hash; reproducibility is via the public ledger + public verification.