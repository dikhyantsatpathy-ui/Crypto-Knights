=====================================================================
  NO CAP (Crypto-Knights) — BACKEND STUDY GUIDE & BUZZWORD DICTIONARY
  For IDEATHON / SIH presentation. Explained in simple, layman terms.
=====================================================================

  Read this top to bottom. Then drill yourself on the Q&A grill at the
  end. Every concept is explained so you can answer "why" and "what does
  that mean", not just quote code.

=====================================================================
  PART 0 — THREE FACTS YOU MUST GET RIGHT (or you'll be caught out)
=====================================================================

  1) THERE IS NO QR CODE. The presentation deck says "visual QR receipt"
     and "ReportLab" — but the CODE has zero QR. The real "media trap" is
     HIDDEN METADATA injected into the file's own tag/metadata fields:
        - PDF   -> writer.add_metadata({"/Nocap_Issuer":..., "/Nocap_Signature":...})
        - MP3   -> ID3 TXXX tags (NOCAP_ISSUER, NOCAP_SIG)
        - MP4   -> comment atom ("NOCAP_VERIFIED|ISSUER:...|SIG:...|TIME:...")
     So if they ask "where's the QR?" say: "We display a hash/QR-style
     receipt on the UI, but the anti-tamper mechanism is hidden binary
     metadata injected into the file container (ID3 for audio, MP4 atoms,
     PDF metadata), which survives even if visible watermarks are cropped."
     Do NOT claim ReportLab/QR unless you are prepared to add it.

  2) THERE IS NO POST-QUANTUM CRYPTOGRAPHY. None. No Dilithium, no Kyber,
     no lattice math. "Hybrid" DOES NOT mean "post-quantum + normal."
     If you claim post-quantum and they ask "which algorithm?" you're dead.
     The README even says PQC is a "future" consideration (§13), not a
     feature. Say: "Our current signature is NIST-standard ECDSA P-256.
     We designed the vault and signature format so a Post-Quantum algorithm
     could be swapped in later, but we do not ship PQC today."

  3) "HYBRID" in the code means TWO DIFFERENT THINGS — neither is
     post-quantum:
        (a) A version LABEL. The signature string starts with "hybrid:"
            as a self-describing tag so the verifier knows the format.
        (b) TWO signatures per file (in sign_media): one on the raw bytes
            before the trap is injected, one on the final trapped bytes.
            This is "hybrid verification / dual signature," not hybrid
            encryption. Only ECDSA SECP256R1 is used. Nothing else.

=====================================================================
  PART 0.5 — CODE-GROUNDED FACTS (cite these lines if grilled)
=====================================================================

  These are the EXACT places in app.py that prove each claim. If you
  quote the code, you can't be caught out.

  * Key generation ............ ec.generate_private_key(ec.SECP256R1())
                                  (app.py:284)  -> ECDSA P-256
  * Sign the digest ........... priv_key.sign(text_hash.encode(),
                                  ec.ECDSA(hashes.SHA256())) (app.py:557)
                                  -> signs SHA-256 digest, not the file
  * Verify ................... pub_key.verify(sig, target_hash.encode(),
                                  ec.ECDSA(hashes.SHA256())) (app.py:722)
  * Vault encrypt ............ AESGCM(derive_owner_key(email)).encrypt(...)
                                  (app.py:254-258) -> AES-256-GCM
  * Vault derive ............ HKDF(SHA256, salt=email,
                                  info="nischay-owner-vault-key-v1")
                                  (app.py:250-252) -> per-user key
  * "hybrid" meaning ........ comment: "Two signatures per artifact"
                                  (app.py:622-629) -> DUAL signature,
                                  NOT post-quantum, NOT hybrid encryption
  * Media trap = metadata ... inject_media_trap: PDF add_metadata /
                                  MP3 ID3 TXXX / MP4 comment atom
                                  (app.py:313-349) -> NOT a QR code
  * Trap check .............. extract_media_trap() (app.py:341)
  * Our session cookie ...... email+"::"+HMAC(master,email) (app.py:266)
                                  issued by admin_login AFTER verifying the
                                  Google id_token (app.py:410,416)
  * Merkle root ............. compute_merkle_root() (app.py:351)
  * Chain anchor ............ anchor_merkle_to_chain(): REAL tx if
                                  WEB3_RPC_URL+WALLET_PRIVATE_KEY set,
                                  else "0xSIMULATED_TX_..." (app.py:360)
  * IPFS .................... upload_receipt_to_ipfs(): real Pinata POST
                                  if PINATA_JWT set, else "QmReceipt..."
                                  simulated (app.py:302-311)
  * Async offload ........... run_in_threadpool(_sign_text_core, ...)
                                  (app.py:511)
  * DB cleanup .............. @contextmanager get_db(): yield + finally
                                  db.close() (app.py:237-241)
  * Verdicts ................ no block + trap -> PROVEN_FAKE / no trap ->
                                  UNSIGNED / revoked -> REVOKED / sig ok ->
                                  AUTHENTIC (app.py:704-730)

=====================================================================
  PART 1 — HASHING (SHA-256)
=====================================================================

  WHAT IS A HASH?
  A hash is a fixed-length "fingerprint" of any data. Feed the whole
  internet into SHA-256 and you get one 64-character string. Feed one
  letter and you ALSO get a 64-character string.

  WHY IS "SAME INPUT -> SAME HASH"?
  A hash function is PURE / DETERMINISTIC. It's a math formula with no
  randomness. Put in X, the formula outputs exactly one value. Same X
  always gives same output, every single time, on every machine. That's
  what makes it useful as an identifier: two people can compute it
  independently and compare.

  WHY IS IT "ONE-WAY"?
  Because the formula is designed to be impossible to reverse. Think of
  it like making scrambled eggs: easy to scramble, practically impossible
  to un-scramble back into the egg. Or like a blender: you can't recover
  an intact apple from applesauce.
  The math: SHA-256 performs ~64 rounds of bit-mixing and modular
  addition. There's no shortcut — to find an input that produces a given
  hash you'd have to try ~2^256 guesses (astronomically impossible).
  So you can verify "this data produced this hash" but you can never get
  the original data back out of a hash.

  WHY DOES AVALANCHE MATTER?
  Change ONE byte (even one bit) of the input and the output hash changes
  completely. So if someone edits a signed file even slightly, the hash
  recomputed at verification will be totally different from the stored
  hash -> the system knows it was tampered with. This is HOW we detect
  editing.

  LAYMAN ONE-LINER:
  "A hash is a tamper-proof fingerprint — same file always gives the same
  fingerprint, but you can't turn a fingerprint back into a file, and any
  tiny edit changes the fingerprint completely."

  HASHING ALONE IS NOT ENOUGH (know this!)
  Anyone can hash a fake file too. A hash only proves "this content equals
  the content that was hashed" (integrity). It does NOT prove "it came
  from the institution" (authenticity). For authenticity you need a
  DIGITAL SIGNATURE (below).

=====================================================================
  PART 2 — SYMMETRIC vs ASYMMETRIC CRYPTO (the #1 confusion)
=====================================================================

  SYMMETRIC (ONE key, e.g. AES):
    - You have ONE secret key.
    - Same key encrypts AND decrypts.
    - Like a single padlock: the same key locks and unlocks it.
    - PROBLEM: you must share the key with the other party, and if they
      have the key they can also DECRYPT everything and they can also
      FORGE your messages. Key distribution is the weak point.

  ASYMMETRIC (TWO keys — a mathematically linked PAIR):
    - You have a PRIVATE key (secret, only you) and a PUBLIC key (freely
      shared with the whole world).
    - They are a pair: what one encrypts, the other decrypts, and only
      that pair works together.
    - Like a mailbox: anyone can push mail in through the slot (public
      key = everyone can encrypt TO you), but only you have the key to
      open it (private key = only you can decrypt).
    - The beauty: you NEVER share your private key. You share the public
      key freely. So even if the whole world has your public key, nobody
      can sign as you.

  WHERE DOES THE PUBLIC KEY COME FROM? (Your question!)
    The public key is NOT "given to you" by anyone. It is COMPUTED from
    the private key using math (elliptic-curve multiplication). You pick
    a random secret number = private key. You run elliptic-curve math on
    it = public key. So: private key -> (math) -> public key, but you
    CANNOT go backward (public key -> private key) because that math has
    no inverse shortcut (the "trapdoor"/discrete-log problem).
    In the app: when an authority registers, the SERVER generates the
    private key, computes the public key, stores BOTH. Public key goes
    into the public record on each block so anyone can verify.

=====================================================================
  PART 3 — DIGITAL SIGNATURES & THE "DIGEST"
=====================================================================

  WHAT IS A DIGEST?
  "Digest" is just the technical word for the OUTPUT of a hash function —
  the fixed-length fingerprint string. "SHA-256 digest" = the 64-char
  hash. It's called a digest because it "digests" (absorbs/refines) the
  whole input into a compact summary. (Also called a "message digest" or
  "hash value".)

  HOW SIGNING ACTUALLY WORKS (memorize the flow):
    1. Signer computes the file's digest:  D = SHA-256(file)
    2. Signer ENCRYPTS that digest with their PRIVATE key:
         signature = encrypt_private(D)
    3. Signer publishes: the file + the signature + their PUBLIC key.
    4. Verifier:
         a. computes D' = SHA-256(file) themselves
         b. DECRYPTS the signature with the PUBLIC key -> gets D
         c. if D' == D -> authentic + untampered ("AUTHENTIC")
            if not -> not authentic ("PROVEN FAKE" / tampered)

  WHY SIGN THE DIGEST, NOT THE WHOLE FILE?
  Because signing (ECDSA math) is heavier than hashing. Hash the file
  first (fast, even for video), then sign only the tiny digest. Same
  security: the signature is bound to the file because the digest comes
  from the file. This is standard practice (Bitcoin, TLS, PGP all do it).

  WHY CAN'T SOMEONE FORGE IT?
  To forge a signature that verifies under YOUR public key, you'd need
  your PRIVATE key. The public key only checks signatures; it cannot
  create them. Everyone can VERIFY, only the private-key holder can SIGN.
  That's why theft of the private key is the ONLY way to forge — hence
  the server-side vault.

=====================================================================
  PART 4 — THE ACTUAL "HYBRID" (correct the record!)
=====================================================================

  You asked: "isn't hybrid = post-quantum + normal encryption?"
  ANSWER: No. There is no post-quantum in this codebase. "hybrid:" is
  two things:

  (a) A FORMAT TAG. Every signature starts with "hybrid:" so the
      verifier/parser knows exactly how to read the bytes that follow.
      It's self-describing versioning, like a file extension. If we later
      add a different scheme we can tell them apart by the prefix.

  (b) In sign_media DUAL signatures. We make TWO ECDSA signatures:
        - one over the RAW bytes (before we inject the trap)
        - one over the FINAL TRAPPED bytes (what ships to the public)
      Why? Because injecting metadata changes the bytes, which changes
      the hash. The public verifies the shipped signature. The pre-trap
      signature lets a forensic examiner prove BOTH the original and the
      shipped version are authentic — "hybrid verification."

  If they ask "is there post-quantum?" -> be honest:
  "Not shipped. Our signature is NIST ECDSA P-256. The architecture
  (server vault + self-describing signature tags) is designed so a
  post-quantum signature could be introduced later, but today it's
  standard ECDSA — and that's intentional, because PQC algorithms are
  still maturing and the standard hasn't fully settled."

=====================================================================
  PART 5 — ELLIPTIC CURVE vs RSA (and what everything means)
=====================================================================

  WHAT IS AN ELLIPTIC CURVE (the layman answer)?
  It's a specific math equation (y^2 = x^3 + ax + b) shaped like a
  flattened loop. Cryptography picks a point P on the curve and does
  "point multiplication": P + P + P ... k times = kP.
  The TRAPDOOR: given k and P it's easy to compute kP, but given only
  kP and P it's astronomically hard to find k ("elliptic curve discrete
  log problem"). So k = private key, kP = public key, and that
  one-way-ness is the whole security.

  WHAT IS ECDSA? (full form)
  E = Elliptic
  C = Curve
  D = Digital
  S = Signature
  A = Algorithm
  -> "Elliptic Curve Digital Signature Algorithm". It's the NIST-standard
     way to make/verify signatures using elliptic-curve math.

  WHAT IS SECP256R1?
    - "sec" = Standards for Efficient Cryptography (a standards group /
      published set of curves).
    - "p" = parameters are defined over a prime field.
    - "256" = 256-bit key size.
    - "r1" = revision 1.
    It's the official name of a specific, audited curve. "P-256" is the
    NIST name for the SAME curve. NIST P-256 == SECP256R1. Same thing.

  WHAT IS NIST? (full form)
  National Institute of Standards and Technology — a US government agency
  that publishes the federal cryptography standards (the "FIPS" series).
  When you say "NIST-standard", you mean "follows the government-approved
  cryptographic spec (FIPS 186-4)."

  WHAT IS RSA? (full form)
  Rivest–Shamir–Adleman — named after the three inventors. It's the
  older, most famous public-key system, based on the difficulty of
  FACTORING huge numbers.

  IS RSA MORE SECURE? THE KEY QUESTION.
  Short answer: Not necessarily. RSA with 2048 bits and ECDSA with 256
  bits are treated as roughly EQUIVALENTLY secure by the standards bodies
  (both are ~"112-128 bit security"). The card is "stronger for the same
  key size", not "more secure overall."

  "IF RSA IS MORE EXPENSIVE, WHY ISN'T IT SAFER?"
  Because difficulty isn't linear. RSA is expensive because its keys are
  HUGE (2048–4096 bits) and its math (big-number exponentiation) is slow.
  But the SECURITY comes from the mathematical problem's hardness, not
  the key size. A 256-bit curve gives the same "impossible to break"
  guarantee as a 3072-bit RSA key, with smaller keys and faster math.
  So RSA isn't "safer because slower" — speed/size are overhead, not
  security. ECDSA gives equal security with less overhead. That's the
  whole point of curves: same wall, smaller door.

=====================================================================
  PART 6 — AES-256-GCM (in detail)
=====================================================================

  WHAT IS AES? (full form)
  Advanced Encryption Standard. The US-government-blessed symmetric block
  cipher, adopted in 2001, used essentially everywhere (disk encryption,
  TLS, wifi).

  "256" — the KEY SIZE.
  AES-256 uses a 256-bit key. A 256-bit key means there are 2^256
  possible keys. To brute-force it you'd have to try them until you hit
  the right one. 2^256 is roughly 10^77 — more than the number of atoms
  in the observable universe (~10^80). Even if every computer on Earth
  worked in parallel for a billion years, they couldn't try a meaningful
  fraction. That's WHY it's "impossible to brute-force": the search space
  is simply beyond physical reach. (Quantum computers about halve it to
  2^128, but 2^128 is still out of reach and that's exactly why the
  README lists PQC as a future upgrade.)

  "GCM" — the MODE.
  GCM = Galois/Counter Mode. It's not the cipher — it's HOW we use AES.
  GCM gives you TWO things at once:
    - ENCRYPTION (confidentiality: hides the data)
    - AUTHENTICATION (integrity: detects if someone tampered with the
      ciphertext)
  So AES-256-GCM = a symmetric encryption scheme that both hides AND
  detects tampering. It's the modern "AEAD" (Authenticated Encryption
  with Associated Data) mode.

  WHERE IS AES USED IN OUR APP?
  The private signing key of each authority is encrypted at rest with
  AES-256-GCM before being stored in the DB. So even if the whole
  database leaked, the private keys are unreadable ciphertext.

=====================================================================
  PART 7 — HKDF (key derivation)
=====================================================================

  FULL FORM: HMAC-based Key Derivation Function.
  WHAT IT DOES: takes ONE master secret and "mixes in" an identifier
  (here: each user's email) to produce a UNIQUE derived key per user.
  WHY: key separation / least privilege. If user A's derived key leaks,
  it only decrypts user A's vault — the master key and all other users
  remain safe. Also: we never store the master key directly; we store
  derived keys.
  ALSO: HKDF is HMAC-based, which means it's tied to a strong one-way
  hash (HMAC-SHA256), keeping the derivation safe from length-extension
  attacks.

=====================================================================
  PART 8 — VAULT / ZERO-TRUST KEY STORAGE
=====================================================================

  WHY NOT STORE THE PRIVATE KEY ON THE USER'S LAPTOP?
  If the key is on the user's machine and the machine is stolen, the key
  is stolen, and the whole system's authenticity collapses.

  OUR MODEL (the "zero-trust" part):
    - Server generates key pair at registration.
    - Private key encrypted with AES-256-GCM (with HKDF-derived per-user
      key) -> stored as enc_priv_key (ciphertext only).
    - At signing time: decrypt in RAM -> use for the ~1ms sign -> purge.
    - Key is NEVER written to disk in plaintext, NEVER sent to browser,
      NEVER cached.

  LAYMAN: "The signing key lives inside the server's vault. It's stored
  encrypted; it exists in readable form only for the split second of
  signing, inside memory, then it's wiped. Nobody — not even the
  authority themselves — ever holds the raw key."

=====================================================================
  PART 9 — THE MEDIA TRAP (anti-photoshop, NOT a QR)
=====================================================================

  PROBLEM: visible watermarks get photoshopped off.
  SOLUTION: embed authentication data INSIDE the file's own structure.
    - PDF: writes "/Nocap_Issuer", "/Nocap_Signature", "/Nocap_Timestamp"
      into the PDF metadata dictionary.
    - MP3/WAV: writes hidden ID3 frames (TXXX) NOCAP_ISSUER / NOCAP_SIG.
    - MP4: writes a comment atom containing "NOCAP_VERIFIED|ISSUER:...|SIG:...".
  On verify we RE-EXTRACT and check:
    - trap present + hash matches  -> AUTHENTIC
    - trap present but binary altered -> PROVEN FAKE ("FORENSIC TRAP
      TRIGGERED: DEEPFAKE")
  WHY IT BEATS CROPPING/PHOTOSHOP: the hidden data is in the file
  container (ID3/atoms/metadata), not in the visible pixels. Editing the
  pixels without breaking the container metadata is trivial to detect.

  LAYMAN: "We don't rely on visible watermarks. We write proof INTO the
  file's brain — the hidden metadata that audio/video/PDF files carry.
  Photoshop the picture all you want; if the hidden proof no longer
  matches the content, we flag it as a fake."

=====================================================================
  PART 10 — MERKLE LEDGER (what it does, why it's there)
=====================================================================

  A MERKLE TREE is a hash tree. Bottom layer = hash of every record.
  Then you hash pairs together, then pairs of those, up to ONE root hash
  (the Merkle ROOT). One small string that summarizes ALL records.

  WHAT IT DOES HERE:
    - Every signed file = a "block" in the ledger (Postgres table "blocks").
    - On /api/blockchain/sync, we compute the Merkle root of ALL block
      hashes and push that single root to a blockchain (or simulated tx).
  WHY (the 3 reasons):
    1. TAMPER-EVIDENCE: It's computationally infeasible to change any
       block without changing the root. If someone alters the DB, the
       Merkle root won't match the on-chain anchor.
    2. VERIFIABLE IN ONE LINE: Instead of anchoring 1000 hashes, we
       anchor ONE root. Show the root on the chain and any record can be
       proven against it.
    3. INTEGRITY vs A SILENT REWRITE: A central DB can be silently
       rewritten by an admin. Anchoring the Merkle root to an immutable
       chain means the DB can't be rewritten without leaving a detectable
       mismatch. (Immutable ledger.)

  LAYMAN: "Think of all our records folded into one giant fingerprint via
  a Merkle tree. We tattoo that fingerprint onto the blockchain. If any
  single record is secretly edited, the fingerprint changes and the
  blockchain no longer matches — so tampering is caught, and caught
  after the fact no matter who did it."

=====================================================================
  PART 11 — IPFS + PINATA (decentralized anchoring)
=====================================================================

  WHAT IS IPFS? (full form)
  InterPlanetary File System. A decentralized, peer-to-peer file network.
  Files are addressed by their CONTENT (a CID = content identifier =
  basically the hash), not by a location/link.

  WHAT WE PIN (privacy trick):
  NOT the raw media. Only a small JSON RECEIPT: {hash, signature, issuer,
  timestamp, (media sha256)}. This is "zero-knowledge" — the outside
  world sees proof, never your private content.

  WHY:
  - Content-addressed + immutable: once pinned, the CID can't be changed.
  - Decentralized: no single server to hack/delete.
  - Independent verifiability: anyone can fetch the receipt and confirm
    the signature/signer/time were exactly as issued, WITHOUT trusting
    our database.

  HONEST CAVEAT (say this openly):
  With no PINATA_JWT, we run SIMULATED mode — we produce a deterministic
  fake CID (QmReceipt<SHA-256>) and don't call Pinata. The architecture
  is real; for the ideathon we don't need a live Pinata/Web3 account.
  If they push: "We architect for real IPFS anchoring; for the demo we
  simulate it so the flow works offline and without external keys. The
  README documents this as an intentional hackathon decision."

=====================================================================
  PART 12 — ASYNC + CONCURRENCY + THE THREADPOOL
=====================================================================

  WHAT IS SYNC vs ASYNC?
  - Sync code: does one task, waits for it to finish, then moves on.
    While it waits (e.g., for a network reply), it's stuck doing nothing.
  - Async code: can START many tasks and not sit idle while waiting. When
    a slow thing (network/DB) is pending, async "parks" it and works on
    something else, then comes back when the slow thing is done.

  HOW ARE REQUESTS CONCURRENT?
  FastAPI (via ASGI) runs an EVENT LOOP. The event loop juggles many
  pending requests at once. While request #1 is waiting for a DB reply,
  the loop doesn't block — it processes request #2, #3, etc. The `async
  def` handlers let the loop interleave work. That's how one server
  appears to handle many users "at the same time" (concurrency).

  "WHY DO WE EVEN NEED TO BLOCK THE EVENT LOOP?"
  The phrase is OUR CHOICE to AVOID blocking it. Here's the thing:
    - A DB call (Neon, over the internet) is SLOW (latency) and it is
      SYNCHRONOUS (blocking) if called inside an async handler without
      care.
    - If we let one slow, synchronous DB call run directly in the event
      loop, the WHOLE server freezes for everyone else until it finishes
      (because the loop is single-threaded and can't multitask while
      blocked).
  THE FIX: `run_in_threadpool`. We take the synchronous/hostile code
  (the ECDSA sign + the DB round-trip) and RUN IT ON A SEPARATE WORKER
  THREAD. The event loop stays free to serve other requests. When the
  worker thread finishes, it hands the result back. So:
    "We run blocking, CPU/network work OFF the event loop (in a
    threadpool) so the async event loop never freezes and the server
    stays responsive under load."

  LAYMAN: "FastAPI is like a waiter who can serve many tables at once, but
  if the kitchen (slow DB) is in the same person, one slow order blocks
  everyone. So we let the kitchen run on its own staff (threadpool) while
  the waiter keeps taking orders."

=====================================================================
  PART 13 — SQLALCHEMY ORM (SQL injection)
=====================================================================

  WHAT: SQLAlchemy is an Object-Relational Mapper — you work with Python
  objects/classes instead of writing raw SQL strings.
  WHY SECURE: user input is bound as typed PARAMETERS, never concatenated
  into a query string. So a malicious input can't be injected as SQL
  commands (`'; DROP TABLE ...`). SQL injection is structurally
  impossible through the ORM.

=====================================================================
  PART 14 — THE 30-SECOND ELEVATOR PITCH (memorize)
=====================================================================

  "We cryptographically sign official media with a NIST-standard ECDSA
  signature. The private key is encrypted in a server-side AES-256-GCM
  vault and only exists in RAM for the instant of signing. A hidden
  metadata trap inside the file catches photoshopping. A privacy-preserving
  receipt is anchored to IPFS and the ledger's Merkle root to the chain.
  Anyone can verify any file as Authentic, Proven Fake, Revoked, or
  Unsigned — and if an institution's key is ever compromised, one click
  revokes their entire signing history. That's how official-ness becomes
  a verifiable mathematical fact instead of a claim."

=====================================================================
  Q&A GRILL — how to answer the tough ones
=====================================================================

  Q: "Is RSA or ECDSA more secure?"
  A: "They're considered roughly equivalent at their standard sizes —
  2048-bit RSA vs 256-bit ECDSA. ECDSA just achieves that security with
  far smaller keys and faster math, which is why we use NIST P-256."

  Q: "What's a digest?"
  A: "The output of a hash function — the fixed-length fingerprint of the
  content. We sign the digest (not the whole file), which is standard
  practice because it's smaller and faster while still being bound to the
  file."

  Q: "Where does the public key come from?"
  A: "It's computed from the private key by elliptic-curve math. You
  choose a secret number (private key), then multiply a curve point by it
  to get the public key. You can't go backward — the math has no easy
  inverse."

  Q: "Is there post-quantum crypto?"
  A: "No, and we don't claim it. Our signature is standard NIST ECDSA
  P-256. The storage and signature format are designed so a PQC algorithm
  could be added later, but today it's standard ECDSA."

  Q: "What does 'hybrid' mean then?"
  A: "Two things, neither is post-quantum: it's a format tag so the
  verifier knows how to read the signature, and in file signing we make
  TWO signatures — one on the raw bytes and one on the trapped bytes that
  ships — so forensic examiners can prove both the original and the
  shipped file are authentic."

  Q: "If a file is trapped but the hash doesn't match, what happens?"
  A: "PROVEN FAKE — 'forensic trap triggered, deepfake.' It means the
  hidden metadata came from us but the content was altered, so someone
  edited it after signing."

  Q: "What if the vault master key leaks?"
  A: "That's the worst case — it can decrypt all private keys. That's why
  the vault uses per-user HKDF-derived keys (least privilege: one leak
  doesn't expose everyone) and why we treat the master key as the crown
  jewel. In practice we'd rotate the master key and re-encrypt."

  Q: "What if two origins sign the exact same file?"
  A: "The DB enforces file_hash is unique — the second sign is a no-op
  (deduped). A re-sign of identical bytes doesn't create a fake new block."

  Q: "Why is the signature made of a hash + ECDSA, not just a hash?"
  A: "A hash proves integrity (nothing changed) but not authenticity
  (who did it). Anybody can hash a file. ECDSA is what binds the hash to
  a specific private key, so only the real issuer's signature validates.
  Hash = what, signature = who."

  Q: "Why is the DB wrapped in a contextmanager?"
  A: "To guarantee the DB connection is ALWAYS released — on success or
  on failure — preventing connection leaks that crash the server under
  concurrency. `with` guarantees cleanup."

  Q: "Why simulate IPFS, isn't that fake?"
  A: "The flow is real; we just substitute a deterministic CID when no
  Pinata key is present so the demo works offline and without external
  accounts. Flip on PINATA_JWT and WEB3_RPC_URL and it anchors for real.
  Reasonable and documented choice for a hackathon."

  Q: "Why do you need the threadpool?"
  A: "DB calls over the internet are slow and synchronous. If they ran in
  the async event loop, one slow request would freeze the whole server.
  Running them on a worker thread keeps the event loop responsive —
  that's the 'server never freezes' concurrency benefit."

  Q: "What's actually stored for each block?"
  A: "signer (email/name/institution/role), filename, file_hash, signature,
  timestamp, IPFS CID, tx_hash, merkle_root, revoked flag, and for
  broadcasts the notice text + optional media. Nothing like raw media or
  emails beyond the signer's own record is exposed publicly."

  Q: "How do you revoke?"
  A: "Set is_revoked on the signer and flip every block they signed to
  revoked. The history stays (audit trail) but verifies as REVOKED. A
  normal signer needs a 5-digit PIN to self-revoke; super admins can
  revoke any."

=====================================================================
  BUZZWORD CHEAT SHEET (30-second definitions)
=====================================================================
  SHA-256 ......... a one-way fingerprint function; 64-char output.
  Hash ............. fixed-length, deterministic, one-way fingerprint.
  Digest ........... the output of a hash.
  Deterministic .... same input always -> same output.
  One-way .......... can't reverse the hash back to the input.
  Avalanche ........ tiny edit -> totally different hash.
  Symmetric ........ one shared key encrypts + decrypts (AES).
  Asymmetric ....... key PAIR: private (secret) + public (shared).
  Private key ...... secret key that signs/decrypts; never shared.
  Public key ....... shared key that verifies/encrypts; safe to publish.
  Signature ........ private-key-encrypted digest, proves who + integrity.
  Non-repudiation .. signer can't deny they signed it.
  ECDSA ............ Elliptic Curve Digital Signature Algorithm.
  SECP256R1 ........ the specific audited curve (== NIST P-256).
  NIST ............. National Institute of Standards and Technology.
  FIPS 186-4 ....... the NIST ECDSA spec.
  RSA .............. Rivest-Shamir-Adleman; factoring-based public key.
  Elliptic curve ... math whose one-way trapdoor gives key security.
  AES .............. Advanced Encryption Standard (symmetric cipher).
  GCM .............. Galois/Counter Mode; encryption + authentication.
  AEAD ............. Authenticated Encryption with Associated Data.
  256-bit key ...... 2^256 keys; brute-force is physically impossible.
  Brute-force ...... try every key until one works; infeasible at 256b.
  HKDF ............. HMAC-based Key Derivation Function (per-user keys).
  Vault ............ encrypted-at-rest store for private keys.
  Zero-trust ....... no party is trusted by default; keys stay server-side
                     in RAM only at signing time.
  KMS .............. Key Management System.
  Media trap ....... hidden metadata injected into file container (ID3,
                     MP4 atom, PDF metadata) to catch editing.
  Merkle tree ...... hash tree; one root summarizes many records.
  Merkle root ...... the single top hash; anchored to chain.
  Ledger ........... append-only record of all signings (blocks table).
  IPFS ............. InterPlanetary File System; decentralized, content-
                     addressed storage.
  CID .............. Content Identifier (= hash) on IPFS.
  Pinata ........... a hosted API to pin files to IPFS.
  Receipt .......... small JSON {hash, sig, issuer, time} — pinned, not
                     the raw media (privacy).
  Async ............. event-loop concurrency; park slow I/O, do other work.
  Event loop ....... single-threaded scheduler that juggles async tasks.
  Threadpool ....... worker threads that run blocking CPU/DB work off the
                     event loop so the server never freezes.
  run_in_threadpool . FastAPI helper that offloads sync work to a thread.
  ORM .............. Object-Relational Mapper (SQLAlchemy) -> parameterized
                     queries -> SQL injection impossible.
  Dependency map ... Vis.js graph of signers/blocks, for visual forensics.
  Retract/Revoke ... mark a notice/signer as no longer authoritative.
  Simulated mode ... deterministic fake CIDs/tx when external keys absent.

=====================================================================
  LAST TIP
=====================================================================
  When they interrupt with "why?", answer the ONE-LINER first, then offer
  the detail sentence. Confidence + honesty beats memorized fluff —
  especially on "is that real?" questions where you must NOT overclaim
  (QR, post-quantum). If unsure, say what the architecture DOES do, not
  what marketing terms you wish it did.
=====================================================================
