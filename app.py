"""
No cap 2.0 - Enterprise Provenance Engine
Organized into strict, human-readable columns for easy debugging.
"""

import hashlib
import hmac
import io
import os
import re
import sys
import threading
import zipfile
import time
import base64
import json
from datetime import datetime, timezone
from typing import List
from contextlib import contextmanager

from dotenv import load_dotenv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, Request, File, Form, HTTPException, UploadFile, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool
from pypdf import PdfReader, PdfWriter

# Media Trapping & Blockchain Dependencies
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError
from mutagen.mp4 import MP4
from web3 import Web3
import requests

from sqlalchemy import create_engine, Column, String, Integer, Boolean, LargeBinary, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.dialects.postgresql import insert as pg_insert

# --- SECURITY DEPENDENCIES ---
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

# ==============================================================================
# [ COLUMN 1: ENVIRONMENT & DB CONFIG ]
# ==============================================================================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "").strip().replace("postgres://", "postgresql://", 1)
if not DATABASE_URL:
    sys.exit("\n[FATAL] DATABASE_URL is not set.\n"
             "  -> Copy .env.example to .env and set DATABASE_URL before starting.\n"
             "  Example: DATABASE_URL=postgresql://USER:PASSWORD@HOST/PORT/DB?sslmode=require\n")

if "sqlite" not in DATABASE_URL:
    import psycopg2

    # Neon DNS on this network is flaky (`could not translate host name ...`).
    # connect_timeout bounds the TCP/SSL phases but NOT DNS resolution, so a
    # transient resolver blip used to hang requests for the OS timeout. Retrying
    # the raw connect a few times turns that into a fast recover instead.
    def _pg_creator():
        last = None
        for attempt in range(3):
            try:
                return psycopg2.connect(DATABASE_URL, connect_timeout=10)
            except Exception as e:
                last = e
                if attempt < 2:
                    time.sleep(0.4 * (attempt + 1))
        raise last or RuntimeError("PostgreSQL connect failed")

    engine = create_engine(DATABASE_URL, pool_pre_ping=True, creator=_pg_creator)

    try:  # prime the OS resolver cache so the first real request rarely hits DNS
        import socket
        _parse = DATABASE_URL.split("//", 1)[1].split("/", 1)[0]
        socket.getaddrinfo(_parse.rsplit(":", 1)[0], int(_parse.rsplit(":", 1)[1] if ":" in _parse else 5432))
    except Exception:
        pass
else:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

RAW_KEY = os.getenv("MASTER_VAULT_KEY", "").encode("utf-8")
if not RAW_KEY:
    sys.exit("\n[FATAL] MASTER_VAULT_KEY is not set.\n"
             "  -> Copy .env.example to .env and set a 32+ byte MASTER_VAULT_KEY.\n"
             "  NOTE: Changing this key AFTER identities exist breaks access to their KMS keys.\n")
MASTER_VAULT_KEY = RAW_KEY.ljust(32, b"0")[:32]

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
if not GOOGLE_CLIENT_ID:
    sys.exit("\n[FATAL] GOOGLE_CLIENT_ID is not set.\n"
             "  -> Set the OAuth 2.0 Client ID of your Google Workspace project in .env.\n")

# --- Web3 & IPFS Config (optional: simulated when empty) ---
WEB3_RPC_URL = os.getenv("WEB3_RPC_URL", "")  
WALLET_PRIV_KEY = os.getenv("WALLET_PRIVATE_KEY", "")
PINATA_JWT = os.getenv("PINATA_JWT", "")
BLOCKCHAIN_EXPLORER_URL = os.getenv("BLOCKCHAIN_EXPLORER_URL", "https://amoy.polygonscan.com/tx/")

# --- Sign-in authorization (NOT hardcoded email lists) -----------------------
# Who may log in is decided by Google Cloud itself:
#   * ALLOWED_DOMAINS  - comma-separated Google-hosted domains (id_token `hd`),
#                        e.g. "soa.ac.in,iter.ac.in". Anyone whose Google Cloud
#                        account belongs to one of these domains is allowed and
#                        is added automatically — no code edit needed.
#   * ALLOWED_EMAILS   - optional comma-separated exact emails (e.g. personal
#                        gmail accounts, which carry no `hd` claim).
# Super admins ALWAYS bypass the gate so the owner can never be locked out.
ALLOWED_DOMAINS = {d.strip().lower() for d in os.getenv("ALLOWED_DOMAINS", "").split(",") if d.strip().lower()}
ALLOWED_EMAILS = {e.strip().lower() for e in os.getenv("ALLOWED_EMAILS", "").split(",") if e.strip().lower()}

SUPER_ADMINS = [
    "asutoshn06@gmail.com",
    "ayushlenka2020@gmail.com",
    "dikhyantsatpathy@gmail.com"
]

def is_super_admin(email: str) -> bool:
    return email.strip().lower() in [e.strip().lower() for e in SUPER_ADMINS]

# ==============================================================================
# [ COLUMN 2: DATABASE MODELS ]
# ==============================================================================

class SignerIdentity(Base):
    __tablename__ = "signer_identities"
    email = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    institution = Column(String, nullable=True)
    designation = Column(String, nullable=True)
    pub_key = Column(String, nullable=False)
    enc_priv_key = Column(String, nullable=False)
    is_revoked = Column(Boolean, default=False)
    registered_at = Column(String, nullable=False)
    revoked_at = Column(String, nullable=True)
    revoke_pin = Column(String, nullable=True)

class LedgerBlock(Base):
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    signer_email = Column(String, nullable=False)
    signer_name = Column(String, nullable=False)
    signer_institution = Column(String, nullable=True)
    signer_designation = Column(String, nullable=True)
    filename = Column(String, nullable=False)
    file_hash = Column(String, unique=True, index=True, nullable=False)
    sig_hex = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    ipfs_cid = Column(String, nullable=True)
    tx_hash = Column(String, nullable=True)       # NEW: Web3 L2 Transaction Hash
    merkle_root = Column(String, nullable=True)   # NEW: Merkle Root
    is_revoked = Column(Boolean, default=False)
    notice_content = Column(String, nullable=True)      # NEW: raw emergency text (public board)
    notice_deleted = Column(Boolean, default=False)     # NEW: retracted by the issuing authority
    notice_media_type = Column(String, nullable=True)   # NEW: MIME type of attached image/video
    notice_media_name = Column(String, nullable=True)   # NEW: original filename of attached media
    notice_media_data = Column(LargeBinary, nullable=True)  # NEW: raw bytes of attached media

class VerificationLog(Base):
    __tablename__ = "verification_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_hash = Column(String, nullable=False)
    status = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)

try:
    Base.metadata.create_all(bind=engine)
except Exception:
    # Best-effort: a transient Neon DNS blip must never abort startup. Schema
    # drift is still handled by the idempotent migration pass below.
    print("[startup] warning: create_all deferred (DB unreachable now).")

_IS_SQLITE = "sqlite" in DATABASE_URL

_MIGRATIONS = [
    "ALTER TABLE signer_identities ADD COLUMN IF NOT EXISTS institution VARCHAR;",
    "ALTER TABLE signer_identities ADD COLUMN IF NOT EXISTS designation VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_email VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_name VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_institution VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS signer_designation VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS tx_hash VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS merkle_root VARCHAR;",
    "ALTER TABLE signer_identities ADD COLUMN IF NOT EXISTS revoke_pin VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_content TEXT;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_deleted BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_media_type VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_media_name VARCHAR;",
    "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS notice_media_data " + ("BYTEA" if not _IS_SQLITE else "BLOB") + ";",
    # Signing latency fix: file_hash is now UNIQUE at the DB level, so a re-sign
    # of identical bytes is a no-op single statement instead of a select+insert.
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_blocks_file_hash ON blocks(file_hash);",
]

print("[startup] running schema migration...")
for stmt in _MIGRATIONS:
    try:
        with engine.begin() as conn:
            conn.execute(text(stmt))
    except Exception: pass
print("[startup] schema migration pass complete.")

if not _IS_SQLITE:
    # The old helper relied on a plain (non-unique) lookup index; the unique
    # index above fully supersedes it. Dropped on Postgres only — sqlite's
    # own ix_blocks_file_hash is the brand-new constraint backing its COLUMN.
    try:
        with engine.begin() as conn:
            conn.execute(text("DROP INDEX IF EXISTS ix_blocks_file_hash;"))
    except Exception:
        pass

# --- Neon (serverless Postgres) pauses after ~5 min of idle; the FIRST request
#     then pays a 5-20s cold start. For demos this reads as "signing is slow",
#     so a lightweight daemon keeps the compute awake. Set KEEPALIVE_INTERVAL=0
#     to disable, or raise it (seconds) for battery-friendlier sleep. ---
def _start_keepalive() -> None:
    if os.getenv("VERCEL") == "1":
        return  # serverless: instances are short-lived, a daemon thread would be pointless
    interval = float(os.getenv("KEEPALIVE_INTERVAL", "45"))
    if _IS_SQLITE or interval <= 0:
        return

    def _ping_loop():
        while True:
            time.sleep(interval)
            try:
                with engine.connect() as c:
                    c.execute(text("SELECT 1"))
            except Exception:
                pass  # network hiccup or explicit shutdown - keep trying

    threading.Thread(target=_ping_loop, daemon=True, name="neon-keepalive").start()

_start_keepalive()

@contextmanager
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def now_utc(): 
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

# ==============================================================================
# [ COLUMN 3: CRYPTOGRAPHY & KMS VAULT ]
# ==============================================================================

def derive_owner_key(owner_email: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=owner_email.strip().lower().encode('utf-8'), info=b"nischay-owner-vault-key-v1")
    return hkdf.derive(MASTER_VAULT_KEY)

def encrypt_vault_key(pem_bytes: bytes, owner_email: str) -> str:
    aesgcm = AESGCM(derive_owner_key(owner_email))
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, pem_bytes, None)
    return base64.b64encode(nonce + ct).decode('utf-8')

def decrypt_vault_key(enc_str: str, owner_email: str) -> bytes:
    data = base64.b64decode(enc_str)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(derive_owner_key(owner_email))
    return aesgcm.decrypt(nonce, ct, None)

def make_session_token(email: str) -> str:
    sig = hmac.new(MASTER_VAULT_KEY, email.strip().lower().encode(), hashlib.sha256).hexdigest()
    return f"{email.strip().lower()}::{sig}"

def get_current_admin(request: Request):
    token = request.cookies.get("nischay_session")
    if not token or "::" not in token:
        raise HTTPException(status_code=401, detail="ACCESS DENIED: Missing or invalid secure session cookie.")
    email, sig = token.rsplit("::", 1)
    expected = hmac.new(MASTER_VAULT_KEY, email.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="ACCESS DENIED: Session signature invalid or tampered.")
    return email

def get_or_create_signer_identity(db, email: str, google_name: str) -> SignerIdentity:
    identity = db.query(SignerIdentity).filter_by(email=email).first()
    if identity: return identity

    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    priv_pem = priv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    enc_priv = encrypt_vault_key(priv_pem.encode('utf-8'), owner_email=email)

    identity = SignerIdentity(
        email=email, name=(google_name or email).strip()[:200], designation=None,
        pub_key=pub_pem, enc_priv_key=enc_priv, registered_at=now_utc()
    )
    db.add(identity)
    db.commit()
    db.refresh(identity)
    return identity

# ==============================================================================
# [ COLUMN 4: DEEPFAKE FORENSICS & WEB3 ANCHORING ]
# ==============================================================================

def upload_receipt_to_ipfs(receipt_dict: dict) -> str:
    """Zero-Knowledge Privacy: Anchors only JSON metadata, preventing plaintext file leaks."""
    if not PINATA_JWT:
        simulated_hash = hashlib.sha256(json.dumps(receipt_dict, sort_keys=True).encode()).hexdigest()
        return f"QmReceipt{simulated_hash[:38]}"
    try:
        receipt_bytes = json.dumps(receipt_dict, indent=2).encode("utf-8")
        res = requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS", headers={"Authorization": f"Bearer {PINATA_JWT}"}, files={"file": (f"receipt_{receipt_dict.get('file_hash', 'blob')[:12]}.json", receipt_bytes)}, timeout=8)
        return res.json().get("IpfsHash", "IPFS_PIN_FAILED")
    except Exception: return "IPFS_NETWORK_ERROR"

def inject_media_trap(file_bytes: bytes, filename: str, signer_label: str, sig_hex: str, timestamp: str) -> bytes:
    """Injects Nocap signatures natively into PDF, MP3, and MP4 containers."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    try:
        if ext == "pdf":
            reader, writer = PdfReader(io.BytesIO(file_bytes)), PdfWriter()
            for page in reader.pages: writer.add_page(page)
            writer.add_metadata({"/Nocap_Issuer": signer_label, "/Nocap_Signature": sig_hex, "/Nocap_Timestamp": timestamp})
            out = io.BytesIO()
            writer.write(out)
            return out.getvalue()
        elif ext in ["mp3", "wav"]:
            audio_io = io.BytesIO(file_bytes)
            try: tags = ID3(audio_io)
            except ID3NoHeaderError: tags = ID3()
            tags.add(TXXX(encoding=3, desc="NOCAP_ISSUER", text=signer_label))
            tags.add(TXXX(encoding=3, desc="NOCAP_SIG", text=sig_hex))
            tags.save(audio_io)
            return audio_io.getvalue()
        elif ext in ["mp4", "m4a", "mov"]:
            mp4_io = io.BytesIO(file_bytes)
            tags = MP4(mp4_io)
            tags["\xa9cmt"] = f"NOCAP_VERIFIED|ISSUER:{signer_label}|SIG:{sig_hex}|TIME:{timestamp}"
            tags.save(mp4_io)
            return mp4_io.getvalue()
    except Exception as e: print(f"Trap warning {ext}: {e}")
    return file_bytes

def extract_media_trap(file_bytes: bytes, filename: str) -> bool:
    """Checks for trapped metadata in manipulated media."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    try:
        if ext == "pdf": return "/Nocap_Issuer" in (PdfReader(io.BytesIO(file_bytes)).metadata or {})
        if ext in ["mp3", "wav"]: return any(isinstance(f, TXXX) and f.desc in ["NOCAP_ISSUER", "NOCAP_SIG"] for f in ID3(io.BytesIO(file_bytes)).values())
        if ext in ["mp4", "m4a", "mov"]: return "NOCAP_VERIFIED" in str(MP4(io.BytesIO(file_bytes)).get("\xa9cmt", [""])[0])
    except Exception: pass
    return False

def compute_merkle_root(leaf_hashes: List[str]) -> str:
    if not leaf_hashes: return hashlib.sha256(b"GENESIS").hexdigest()
    current_level = [bytes.fromhex(h) if len(h) == 64 else hashlib.sha256(h.encode()).digest() for h in leaf_hashes]
    while len(current_level) > 1:
        if len(current_level) % 2 != 0: current_level.append(current_level[-1])
        current_level = [hashlib.sha256(current_level[i] + current_level[i + 1]).digest() for i in range(0, len(current_level), 2)]
    return current_level[0].hex()

def anchor_merkle_to_chain(merkle_root: str) -> str:
    if not WEB3_RPC_URL or not WALLET_PRIV_KEY: return f"0xSIMULATED_TX_{hashlib.sha256(merkle_root.encode()).hexdigest()[:40]}"
    try:
        w3 = Web3(Web3.HTTPProvider(WEB3_RPC_URL))
        account = w3.eth.account.from_key(WALLET_PRIV_KEY)
        tx = {
            'to': account.address, 'value': 0, 'gas': 100000, 'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(account.address),
            'data': Web3.to_bytes(text=f"NOCAP_ROOT:{merkle_root}"), 'chainId': w3.eth.chain_id
        }
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=WALLET_PRIV_KEY)
        raw_tx = getattr(signed_tx, "raw_transaction", getattr(signed_tx, "rawTransaction", None))
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        return w3.to_hex(tx_hash)
    except Exception as e: return "TX_FAILED"

# ==============================================================================
# [ COLUMN 5: FASTAPI SETUP & BASE ROUTES ]
# ==============================================================================

app = FastAPI(title="No Cap · Enterprise Provenance Engine", version="12.0")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
@limiter.limit("120/minute")
def index(request: Request):
    return FileResponse("index.html", headers={"Cache-Control": "no-store"})

@app.get("/main.js")
@limiter.limit("120/minute")
def serve_js(request: Request):
    return FileResponse("main.js", headers={"Cache-Control": "no-store"})

@app.post("/api/admin/login")
@limiter.limit("20/minute")
def admin_login(request: Request, credential: str = Form(...)):
    try:
        idinfo = id_token.verify_oauth2_token(credential, google_requests.Request(), GOOGLE_CLIENT_ID, clock_skew_in_seconds=300)
        email = idinfo.get("email")
        if not email or not idinfo.get("email_verified"): raise ValueError("Google did not return a verified email.")
        email = email.strip().lower()

        # Authorization gate — the allow/deny is driven by Google Cloud itself,
        # not by a hardcoded Python list (see ALLOWED_DOMAINS / ALLOWED_EMAILS).
        #   * ALLOWED_DOMAINS matches BOTH id_token["hd"] (the hosted Google
        #     Workspace domain — the account's domain you manage in Google
        #     Cloud) and the email's own "@domain" suffix (for non-Workspace
        #     accounts). Anyone added to that domain is allowed automatically.
        #   * Exact emails are allow-listed via ALLOWED_EMAILS.
        #   * Super admins always pass so the owner is never locked out.
        allowed = False
        if not is_super_admin(email):
            hd = str(idinfo.get("hd") or "").strip().lower()
            suffix = email.split("@", 1)[1] if "@" in email else ""
            if (hd and hd in ALLOWED_DOMAINS) or (suffix in ALLOWED_DOMAINS):
                allowed = True
            elif email in ALLOWED_EMAILS:
                allowed = True
        else:
            allowed = True

        if not allowed:
            raise ValueError("ACCESS DENIED: your Google account is not authorized to use this system.")

        with get_db() as db: get_or_create_signer_identity(db, email, idinfo.get("name"))
        res = JSONResponse(content={"status": "SUCCESS", "admin": email})
        res.set_cookie(key="nischay_session", value=make_session_token(email), httponly=True, secure=os.getenv("VERCEL") == "1", samesite="lax", max_age=86400)
        return res
    except Exception as e: raise HTTPException(401, f"AUTH FAILED: {str(e)}")

@app.post("/api/admin/logout")
@limiter.limit("20/minute")
def admin_logout(request: Request):
    res = JSONResponse(content={"status": "LOGGED_OUT"})
    res.delete_cookie("nischay_session")
    return res

@app.get("/api/admin/me")
@limiter.limit("120/minute")
def check_auth_status(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=admin).first()
    designation = (identity.designation if identity else None) or None
    institution = (identity.institution if identity else None) or None
    pending = bool(identity and (not designation or not institution))
    return {"status": "AUTHENTICATED", "admin": admin, "name": identity.name if identity else admin,
            "designation": designation, "institution": institution, "pending_approval": pending,
            "is_super_admin": is_super_admin(admin)}

@app.post("/api/admin/assign_role")
@limiter.limit("20/minute")
def assign_role(request: Request, target_email: str = Form(...), designation: str = Form(...), institution: str = Form(...), admin: str = Depends(get_current_admin)):
    """Super-admin only: approve/assign a signer's post & institution. Signers cannot self-assign."""
    if not is_super_admin(admin): raise HTTPException(403, "Super-admin clearance required.")
    target = target_email.strip().lower()
    desig, inst = designation.strip()[:150], institution.strip()[:150]
    if not target or not desig or not inst: raise HTTPException(400, "Target signer, post and institution are required.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=target).first()
        if not identity: raise HTTPException(404, "Signer not found.")
        identity.designation, identity.institution = desig, inst
        db.commit()
    return {"status": "ROLE_ASSIGNED", "email": target, "designation": desig, "institution": inst}

# ==============================================================================
# [ COLUMN 6: SIGNING, BROADCASTS & VERIFICATION ENGINE ]
# ==============================================================================

# --- Shared helpers used by every signing/broadcasting endpoint. Keeping the
#     role guard and key decryption in one place means a signer's privileges are
#     impossible to bypass by calling a "less guarded" route. ---

def _safe_filename(name: str) -> str:
    """Strip any path components a client might smuggle into a filename, so
    download names and ZIP entries can never escape into directories."""
    cleaned = (name or "file").replace("\\", "/").split("/")[-1].strip()
    return cleaned or "file"

_IMAGE_EXT = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp", ".svg": "image/svg+xml"}
_VIDEO_EXT = {".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime", ".ogg": "video/ogg", ".m4v": "video/x-m4v"}

def _guess_media_type(name: str) -> str:
    ext = os.path.splitext((name or "").lower())[1]
    return _IMAGE_EXT.get(ext) or _VIDEO_EXT.get(ext) or "application/octet-stream"

def _is_broadcast_media(mime: str) -> bool:
    return (mime or "").startswith("image/") or (mime or "").startswith("video/")

def load_active_signer(db, admin: str):
    """Resolve + authorise a signer for a signing request.

    Returns (identity, institution, role, private_key). Raises 403 unless the
    caller is a registered, non-revoked signer whose post & institution were
    approved by a super admin — signing with a self-typed title is impossible."""
    identity = db.query(SignerIdentity).filter_by(email=admin).first()
    if not identity or identity.is_revoked:
        raise HTTPException(403, "Invalid or revoked identity.")
    institution = (identity.institution or "").strip()
    role = (identity.designation or "").strip()
    if not institution or not role:
        raise HTTPException(403, "Role pending: a super admin must approve your post & institution before you can sign.")
    priv_key = serialization.load_pem_private_key(
        decrypt_vault_key(identity.enc_priv_key, identity.email), password=None)
    return identity, institution, role, priv_key

def insert_block_once(db, **fields) -> bool:
    """Append a ledger block unless the artifact was already signed. file_hash
    is UNIQUE at the DB level, so re-signing identical bytes is an atomic
    no-op instead of a select-then-insert race.

    Returns True when a NEW block was written, False when the hash already
    existed (dup). The INSERT runs inside the session's own transaction; the
    CALLER commits so sign/broadcast flows persist exactly as add()+commit()."""
    if _IS_SQLITE:
        if db.query(LedgerBlock).filter_by(file_hash=fields["file_hash"]).first():
            return False
        db.add(LedgerBlock(**fields))
        return True
    result = db.execute(pg_insert(LedgerBlock).values(**fields).on_conflict_do_nothing(index_elements=["file_hash"]))
    return (result.rowcount or 0) > 0

@app.post("/api/sign_text")
@limiter.limit("40/minute")
async def sign_text_notice(request: Request, message: str = Form(...), broadcast_title: str = Form("Emergency Notice"), urgency_level: str = Form("HIGH"),
                           media: UploadFile = File(None), admin: str = Depends(get_current_admin)):
    """Signs an Emergency Broadcast (text + optional image/video) and returns a
    verifiable JSON receipt.

    Returns plain JSON (no forced attachment download) so the client never has
    to read a response body twice. The ECDSA sign is ~1ms; Neon round trips are
    the only cost, handled in a threadpool and deduped by the unique index."""
    clean_msg = message.strip()
    if not clean_msg:
        raise HTTPException(400, "Message body empty.")
    if urgency_level not in {"CRITICAL", "HIGH", "ADVISORY"}:
        raise HTTPException(400, "Invalid urgency level.")
    broadcast_title = broadcast_title.strip()[:120] or "Emergency Notice"

    media_bytes = None
    media_type = None
    media_name = None
    if media and media.filename:
        media_bytes = await media.read()
        if media_bytes:
            media_name = _safe_filename(media.filename)
            media_type = media.content_type or _guess_media_type(media_name)
            if not _is_broadcast_media(media_type):
                raise HTTPException(400, "Attached media must be an image or video file.")

    # The signed payload binds the message text AND any embedded media, so a
    # swapped-out image/video cannot sneak past verification.
    payload = clean_msg.encode("utf-8") + (b"\x00MEDIA\x00" + media_bytes if media_bytes else b"")
    text_hash = hashlib.sha256(payload).hexdigest()

    result = await run_in_threadpool(
        _sign_text_core, admin, clean_msg, broadcast_title, urgency_level, text_hash,
        media_bytes, media_type, media_name,
    )
    return JSONResponse(result)

def _sign_text_core(admin: str, clean_msg: str, broadcast_title: str, urgency_level: str, text_hash: str,
                    media_bytes, media_type, media_name) -> dict:
    """Synchronous core of the broadcast (sign + provenance insert). Kept out of
    the event loop so a slow Neon round trip never freezes the whole app."""
    with get_db() as db:
        identity, institution, role, priv_key = load_active_signer(db, admin)
        timestamp = now_utc()
        sig_hex = f"hybrid:{priv_key.sign(text_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()}"

        receipt = {
            "version": "nocap-v2-emergency", "title": broadcast_title, "urgency": urgency_level, "content": clean_msg,
            "file_hash": text_hash, "signature": sig_hex, "timestamp": timestamp,
            "signer": {"name": identity.name, "institution": institution, "designation": role},
        }
        if media_bytes:
            receipt["media"] = {
                "name": media_name,
                "type": media_type,
                "sha256": hashlib.sha256(media_bytes).hexdigest(),
            }
        cid = upload_receipt_to_ipfs(receipt)

        # Unique-hash dedup: active notices re-sign as a no-op. A *retracted*
        # notice resurrects only when its ORIGINAL issuer re-issues the exact
        # text — the original pubkey is embedded in the row, so anyone else's
        # signature would make verification report PROVEN_FAKE.
        existing = db.query(LedgerBlock).filter_by(file_hash=text_hash).first()
        if existing and existing.notice_deleted and (existing.signer_email or "").strip().lower() == admin.strip().lower():
            existing.notice_deleted = False
            existing.notice_content = clean_msg
            existing.timestamp = timestamp
            existing.sig_hex = sig_hex
            existing.ipfs_cid = cid
            existing.notice_media_type = media_type
            existing.notice_media_name = media_name
            existing.notice_media_data = media_bytes
            persisted = True
        elif existing:
            persisted = False
        else:
            insert_block_once(
                db,
                signer_email=identity.email, signer_name=identity.name,
                signer_institution=institution, signer_designation=f"EMERGENCY ({urgency_level})",
                filename=f"NOTICE_{broadcast_title[:20]}.json", file_hash=text_hash,
                sig_hex=sig_hex, timestamp=timestamp, ipfs_cid=cid,
                notice_content=clean_msg,
                notice_media_type=media_type,
                notice_media_name=media_name,
                notice_media_data=media_bytes,
            )
            persisted = True
        db.commit()
    return {"receipt": receipt, "ipfs_cid": cid, "ledger_persisted": persisted, "ledger_hash": text_hash}

@app.post("/api/sign")
@limiter.limit("60/minute")
async def sign_media(request: Request, files: List[UploadFile] = File(...), admin: str = Depends(get_current_admin)):
    if not files:
        raise HTTPException(400, "No files.")

    with get_db() as db:
        identity, institution, role, priv_key = load_active_signer(db, admin)
        timestamp, ready = now_utc(), []
        signer_label = f"{identity.name} ({role}, {institution})"

        for f in files:
            raw = await f.read()
            if not raw:
                continue
            safe_name = _safe_filename(f.filename)

            # Two signatures per artifact: one on the pre-trap bytes (kept for
            # forensic comparison) and the authoritative one over the final
            # trapped payload that actually ships to the public.
            raw_hash = hashlib.sha256(raw).hexdigest()
            sig_hex = f"hybrid:{priv_key.sign(raw_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()}"
            trapped = inject_media_trap(raw, safe_name, signer_label, sig_hex, timestamp)
            final_hash = hashlib.sha256(trapped).hexdigest()
            final_sig = f"hybrid:{priv_key.sign(final_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()}"

            cid = upload_receipt_to_ipfs({"filename": safe_name, "file_hash": final_hash, "signature": final_sig, "issuer": signer_label, "timestamp": timestamp})
            insert_block_once(
                db,
                signer_email=identity.email, signer_name=identity.name,
                signer_institution=institution, signer_designation=role,
                filename=safe_name, file_hash=final_hash, sig_hex=final_sig,
                timestamp=timestamp, ipfs_cid=cid,
            )
            ready.append({"name": f"signed_{safe_name}", "bytes": trapped})

        db.commit()  # persist every ledger block written above (see insert_block_once)
        if not ready:
            raise HTTPException(400, "No content to sign.")

        if len(ready) == 1:
            return Response(ready[0]["bytes"], media_type="application/octet-stream",
                            headers={"Content-Disposition": f'attachment; filename="{ready[0]["name"]}"'})
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            for item in ready:
                zf.writestr(item["name"], item["bytes"])
        return Response(mem_zip.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="signed_batch.zip"'})

async def resolve_verify_input(file, client_hash: str, filename: str):
    """Normalise any verify request into (raw_bytes, display_name, target_hash).

    A JSON receipt carries its authoritative file_hash inside it (that's the
    whole point of the receipt), so that wins over re-hashing the bytes."""
    if file is not None:
        raw = await file.read()
        name = _safe_filename(file.filename) or filename or "file"
        if name.lower().endswith(".json"):
            try:
                receipt_hash = json.loads(raw.decode()).get("file_hash")
            except Exception:
                receipt_hash = None
            target_hash = receipt_hash or hashlib.sha256(raw).hexdigest()
        else:
            target_hash = hashlib.sha256(raw).hexdigest()
        return raw, name, target_hash

    if client_hash:
        client_hash = client_hash.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{1,128}", client_hash):
            raise HTTPException(400, "client_hash must be hexadecimal.")
        return b"", filename or "hash_query", client_hash

    raise HTTPException(400, "Provide media, hash, or text.")

@app.post("/api/verify")
@limiter.limit("120/minute")
async def verify_media(request: Request, file: UploadFile = None, client_hash: str = Form(None), filename: str = Form("file"), raw_text: str = Form(None)):
    if raw_text and raw_text.strip():
        # Broadcast path: the alert text itself is the hashed, signed artifact.
        raw = raw_text.strip().encode("utf-8")
        display_name = "emergency_broadcast.txt"
        target_hash = hashlib.sha256(raw).hexdigest()
        has_trap = False
    else:
        raw, display_name, target_hash = await resolve_verify_input(file, client_hash, filename)
        # A forensic trap can only exist on media that passed through our
        # signer, so one on a hash outside the ledger is proof of tampering.
        has_trap = extract_media_trap(raw, display_name) if raw else False

    with get_db() as db:
        def log_and_return(verdict, msg, signer=None, tx_hash=None, retracted=False):
            db.add(VerificationLog(file_hash=target_hash, status=verdict, timestamp=now_utc()))
            db.commit()
            return {"verdict": verdict, "message": msg, "hash": target_hash, "filename": display_name,
                    "signer": signer, "tx_hash": tx_hash, "retracted": retracted,
                    "blockchain_explorer": f"{BLOCKCHAIN_EXPLORER_URL}{tx_hash}" if tx_hash else None}

        block = db.query(LedgerBlock).filter_by(file_hash=target_hash).first()
        if not block:
            verdict = "PROVEN_FAKE" if has_trap else "UNSIGNED"
            msg = ("FORENSIC TRAP TRIGGERED: Metadata detected but binary altered. DEEPFAKE."
                   if has_trap else "Hash not found in ledger.")
            return log_and_return(verdict, msg)

        signer_info = {"name": block.signer_name, "institution": block.signer_institution, "designation": block.signer_designation}
        identity = db.query(SignerIdentity).filter_by(email=block.signer_email).first()
        # Orphaned/revoked signer (e.g. a block left behind by a decommissioned
        # identity) must never 500 — the honest verdict is that the key is gone.
        if not identity or identity.is_revoked or block.is_revoked:
            return log_and_return("REVOKED", f"Key belonging to {block.signer_name} revoked.",
                                  signer=signer_info, tx_hash=block.tx_hash)

        try:
            parts = block.sig_hex.split(":")
            pub_key = serialization.load_pem_public_key(identity.pub_key.encode())
            pub_key.verify(bytes.fromhex(parts[1] if len(parts) > 1 else block.sig_hex),
                           target_hash.encode(), ec.ECDSA(hashes.SHA256()))
            return log_and_return("AUTHENTIC",
                                  ("Verified. Signed by " + block.signer_name + ".") +
                                  (" (notice retracted by issuing authority)." if block.notice_deleted else ""),
                                  signer=signer_info, tx_hash=block.tx_hash,
                                  retracted=bool(block.notice_deleted))
        except Exception:
            return log_and_return("PROVEN_FAKE", "Signature mismatch. Binary altered.", signer=signer_info)

# ==============================================================================
# [ EMERGENCY NOTICE BOARD — public feed + authority retraction ]
# ==============================================================================

def _viewer_from_cookies(request: Request) -> str | None:
    """Best-effort resolve of the optional admin session cookie. Public feed
    stays anonymous; only a valid session grants per-row delete permissions."""
    token = request.cookies.get("nischay_session")
    if not token or "::" not in token:
        return None
    email, sig = token.rsplit("::", 1)
    expected = hmac.new(MASTER_VAULT_KEY, email.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return email

def _notice_urgency(designation: str | None) -> str:
    m = re.match(r"EMERGENCY\s*\((.+)\)", designation or "")
    return m.group(1).strip().upper() if m else ""

@app.get("/api/broadcasts")
@limiter.limit("120/minute")
def public_broadcasts(request: Request, limit: int = 25):
    """Public, unauthenticated feed of live official emergency notices."""
    try:
        limit = max(1, min(int(limit), 500))
    except Exception:
        limit = 25
    viewer = (_viewer_from_cookies(request) or "").strip().lower()

    with get_db() as db:
        rows = (
            db.query(LedgerBlock)
            .filter(LedgerBlock.signer_designation.like("EMERGENCY%"), LedgerBlock.notice_deleted.is_(False))
            .order_by(LedgerBlock.timestamp.desc())
            .limit(limit)
            .all()
        )
        out = []
        for b in rows:
            owner = (b.signer_email or "").strip().lower()
            is_mine = bool(viewer) and owner == viewer
            out.append({
                "title": re.sub(r"^NOTICE_", "", b.filename or "").replace(".json", "")[:140] or "Emergency Notice",
                "urgency": _notice_urgency(b.signer_designation),
                "content": b.notice_content or "",
                "signer": b.signer_name,
                "institution": b.signer_institution or "Independent",
                "designation": b.signer_designation or "",
                "timestamp": b.timestamp,
                "file_hash": b.file_hash,
                "signature": b.sig_hex,
                "ipfs_cid": b.ipfs_cid or "",
                "media_type": b.notice_media_type or "",
                "media_name": b.notice_media_name or "",
                "has_media": bool(b.notice_media_data),
                "is_mine": is_mine,
                "can_delete": bool(viewer) and (is_mine or is_super_admin(viewer)),
            })
    return {"broadcasts": out, "authed": bool(viewer)}

@app.get("/api/broadcasts/{file_hash}/media")
@limiter.limit("120/minute")
def broadcast_media(request: Request, file_hash: str):
    """Publicly serve the media (image/video) attached to an emergency notice.

    The media bytes are stored alongside the signed notice, so the served file
    is exactly the bytes that were bound into the notice's hash at issue time —
    serving it here keeps the board renderable without leaking raw DB blobs."""
    fh = file_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fh):
        raise HTTPException(400, "Invalid ledger hash.")
    with get_db() as db:
        blk = (
            db.query(LedgerBlock)
            .filter(LedgerBlock.file_hash == fh, LedgerBlock.signer_designation.like("EMERGENCY%"),
                    LedgerBlock.notice_deleted.is_(False))
            .first()
        )
        if not blk or not blk.notice_media_data:
            raise HTTPException(404, "No attached media for this notice.")
        data = bytes(blk.notice_media_data)
        media_type = blk.notice_media_type or _guess_media_type(blk.notice_media_name or "")
    return Response(content=data, media_type=media_type,
                    headers={"Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff"})

@app.post("/api/broadcasts/delete")
@limiter.limit("30/minute")
def delete_broadcast(request: Request, file_hash: str = Form(...), admin: str = Depends(get_current_admin)):
    """Retract a live emergency notice. Admins may only retract their own;
    super admins may retract any broadcast."""
    fh = file_hash.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", fh):
        raise HTTPException(400, "Invalid ledger hash.")
    with get_db() as db:
        blk = (
            db.query(LedgerBlock)
            .filter(LedgerBlock.file_hash == fh, LedgerBlock.signer_designation.like("EMERGENCY%"))
            .first()
        )
        if not blk:
            raise HTTPException(404, "Broadcast not found.")
        title = blk.filename
        if not is_super_admin(admin) and (blk.signer_email or "").strip().lower() != admin.strip().lower():
            raise HTTPException(403, "You may only retract notices you issued.")
        blk.notice_deleted = True
        db.commit()
    return {"ok": True, "file_hash": fh, "title": title}

# ==============================================================================
# [ COLUMN 7: SYSTEM COMMANDS & WEB3 SYNC ]
# ==============================================================================

@app.post("/api/blockchain/sync")
@limiter.limit("10/minute")
def sync_ledger_to_blockchain(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        unanchored = db.query(LedgerBlock).filter(LedgerBlock.tx_hash == None).all()
        if not unanchored: return {"status": "UP_TO_DATE", "message": "All blocks anchored."}
        m_root = compute_merkle_root([b.file_hash for b in unanchored])
        tx_hash = anchor_merkle_to_chain(m_root)
        for b in unanchored:
            b.tx_hash = tx_hash
            b.merkle_root = m_root
        db.commit()
    return {"status": "SUCCESS", "anchored_blocks_count": len(unanchored), "merkle_root": m_root, "tx_hash": tx_hash}

@app.post("/api/set_pin")
@limiter.limit("20/minute")
def set_pin(request: Request, pin: str = Form(...), admin: str = Depends(get_current_admin)):
    # Storing a malformed PIN would lock the signer out of self-revocation.
    pin = pin.strip()
    if not pin.isdigit() or len(pin) != 5:
        raise HTTPException(400, "PIN must be exactly 5 digits.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=admin).first()
        if not identity:
            raise HTTPException(404, "Signer not found.")
        identity.revoke_pin = pin
        db.commit()
    return {"status": "PIN_SET"}

@app.post("/api/revoke")
@limiter.limit("20/minute")
def revoke(request: Request, target_email: str = Form(...), pin: str = Form(None), admin: str = Depends(get_current_admin)):
    target = target_email.strip().lower()
    if not is_super_admin(admin) and target != admin.strip().lower(): raise HTTPException(403, "ACCESS DENIED.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=target).first()
        if not identity: raise HTTPException(404, "Not found.")
        if not is_super_admin(admin):
            if not pin or len(pin.strip()) != 5: raise HTTPException(400, "Valid 5-digit PIN required.")
            if identity.revoke_pin and str(identity.revoke_pin) != str(pin.strip()): raise HTTPException(403, "Incorrect PIN.")
            else: identity.revoke_pin = str(pin.strip())
        identity.is_revoked, identity.revoked_at = True, now_utc()
        db.query(LedgerBlock).filter_by(signer_email=identity.email).update({"is_revoked": True})
        db.commit()
    return {"status": "REVOKED"}

@app.post("/api/reinstate")
@limiter.limit("20/minute")
def reinstate(request: Request, target_email: str = Form(...), pin: str = Form(...), admin: str = Depends(get_current_admin)):
    if not is_super_admin(admin): raise HTTPException(403, "Super-admin required.")
    with get_db() as db:
        identity = db.query(SignerIdentity).filter_by(email=target_email.strip().lower()).first()
        if not identity: raise HTTPException(404, "Not found.")
        if identity.revoke_pin and str(identity.revoke_pin) != str(pin.strip()): raise HTTPException(403, "Incorrect PIN.")
        elif not identity.revoke_pin and str(pin.strip()) != "00000": raise HTTPException(403, "Enter 00000 to bypass.")
        identity.is_revoked, identity.revoked_at = False, None
        db.query(LedgerBlock).filter_by(signer_email=identity.email).update({"is_revoked": False})
        db.commit()
    return {"status": "REINSTATED"}

@app.post("/api/dday")
@limiter.limit("10/minute")
def execute_dday(request: Request, admin: str = Depends(get_current_admin)):
    if not is_super_admin(admin): raise HTTPException(403, "ACCESS DENIED.")
    with get_db() as db:
        ts = now_utc()
        for i in range(5): db.add(LedgerBlock(signer_email="hacker@unknown.invalid", signer_name="MALICIOUS ACTOR", filename=f"URGENT_{i}.mp4", file_hash=f"badhash{i}{time.time()}", sig_hex="standard:forged", timestamp=ts, ipfs_cid="UNVERIFIED", is_revoked=True))
        for i in range(15): db.add(VerificationLog(file_hash=f"spam{i}{time.time()}", status="PROVEN_FAKE", timestamp=ts))
        db.commit()
    return {"status": "DDAY_ACTIVE"}

@app.post("/api/rollback")
@limiter.limit("10/minute")
def execute_rollback(request: Request, target_timestamp: str = Form(...), admin: str = Depends(get_current_admin)):
    if not is_super_admin(admin): raise HTTPException(403, "ACCESS DENIED.")
    with get_db() as db:
        db.query(LedgerBlock).filter(LedgerBlock.timestamp > target_timestamp).delete()
        db.query(VerificationLog).filter(VerificationLog.timestamp > target_timestamp).delete()
        db.commit()
        return {"status": "SUCCESS"}

# ==============================================================================
# [ COLUMN 8: DASHBOARDS & TELEMETRY ]
# ==============================================================================

def scoped_queries(db, admin: str, privileged: bool):
    """Resolve how much of the signed world a caller may see: normal signers only
    their own signer rows + blocks; super admins get the full network."""
    signers = db.query(SignerIdentity).all() if privileged else db.query(SignerIdentity).filter_by(email=admin).all()
    blocks = db.query(LedgerBlock).order_by(LedgerBlock.id.desc()).all() if privileged \
        else db.query(LedgerBlock).filter_by(signer_email=admin).order_by(LedgerBlock.id.desc()).all()
    return signers, blocks

@app.get("/api/ledger")
@limiter.limit("120/minute")
def get_ledger(request: Request, admin: str = Depends(get_current_admin)):
    privileged = is_super_admin(admin)
    with get_db() as db:
        signers, block_rows = scoped_queries(db, admin, privileged)

        signers_out = {}
        for s in signers:
            signer_data = {
                "email": s.email, "name": s.name,
                "designation": s.designation or "", "institution": s.institution or "",
                "is_revoked": s.is_revoked, "has_pin": bool(s.revoke_pin),
            }
            # Key Issuance Ledger requirement: exact registration dates are a
            # super-admin-only audit affordance.
            if privileged:
                signer_data["registered_at"] = s.registered_at
                signer_data["revoked_at"] = s.revoked_at
            signers_out[s.email] = signer_data

        blocks_out = []
        for b in block_rows:
            parts = b.sig_hex.split(":")
            crypto_mode = parts[0] if len(parts) > 1 else "standard"
            blocks_out.append({
                "id": b.id, "signer_email": b.signer_email, "signer_name": b.signer_name,
                "signer_institution": b.signer_institution, "signer_designation": b.signer_designation,
                "filename": b.filename, "file_hash": b.file_hash, "sig_hex": b.sig_hex,
                "timestamp": b.timestamp, "ipfs_cid": b.ipfs_cid, "tx_hash": b.tx_hash,
                "merkle_root": b.merkle_root, "is_revoked": b.is_revoked,
                "crypto_mode": crypto_mode, "is_compromised": crypto_mode == "standard",
            })

    return {"signers": signers_out, "blocks": blocks_out, "total": len(blocks_out), "is_super_admin": privileged}

@app.get("/api/analytics")
@limiter.limit("120/minute")
def get_analytics(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        stats = {"AUTHENTIC": 0, "PROVEN_FAKE": 0, "REVOKED": 0, "UNSIGNED": 0}
        for log in db.query(VerificationLog).all():
            stats[log.status] = stats.get(log.status, 0) + 1
    return {"stats": stats}

@app.get("/api/network")
@limiter.limit("60/minute")
def get_network_graph(request: Request, admin: str = Depends(get_current_admin)):
    privileged = is_super_admin(admin)
    with get_db() as db:
        signers, block_rows = scoped_queries(db, admin, privileged)
        nodes = [
            {"id": s.email, "label": s.name + (f" ({s.designation})" if s.designation else ""),
             "group": "authority", "is_revoked": s.is_revoked}
            for s in signers
        ]
        edges = []
        for b in block_rows:
            crypto_mode = b.sig_hex.split(":")[0] if ":" in b.sig_hex else "standard"
            # Compromised files (signed in the old, pre-hybrid mode) get flagged.
            is_compromised = crypto_mode != "hybrid"
            nodes.append({"id": b.file_hash, "label": b.filename, "group": "file",
                          "is_revoked": b.is_revoked, "crypto_mode": crypto_mode,
                          "is_compromised": is_compromised})
            edges.append({"from": b.signer_email, "to": b.file_hash})
        return {"nodes": nodes, "edges": edges}

@app.get("/api/stats")
@limiter.limit("120/minute")
def public_stats(request: Request):
    # Aggregate-only, auth-free counters (no PII) so the landing hero can show live network health.
    with get_db() as db:
        return {
            "signed_docs": db.query(LedgerBlock).count(),
            "trusted_issuers": db.query(SignerIdentity).count(),
        }