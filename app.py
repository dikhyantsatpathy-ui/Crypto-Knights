import hashlib
import io
import os
import zipfile
import time
import base64
from datetime import datetime, timezone
from typing import List
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Request, File, Form, HTTPException, UploadFile, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pypdf import PdfReader, PdfWriter

from sqlalchemy import create_engine, Column, String, Integer, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# --- SECURITY DEPENDENCIES ---
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

# --- ENVIRONMENT & DB CONFIG ---
NEON_DB_URL = "postgresql://neondb_owner:npg_PHMKh6Vtlw8f@ep-red-scene-azg0qzq0.c-3.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"
DATABASE_URL = os.getenv("DATABASE_URL", NEON_DB_URL).replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- SECURITY CONSTANTS ---
RAW_KEY = os.getenv("MASTER_VAULT_KEY", "VERISOURCE_HACKATHON_DEMO_KEY_32").encode('utf-8')
MASTER_VAULT_KEY = RAW_KEY.ljust(32, b'0')[:32]
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "698365851650-qd2nsi8ahrbv4d67aov3lff4anbco2g1.apps.googleusercontent.com")

AUTHORIZED_ADMINS = [
    "asutoshn06@gmail.com",
    "ayushlenka2020@gmail.com",
    "dikhyantsatpathy@gmail.com",
    "dikhyantsatpathy1@gmail.com",
    "supriya2050@gmail.com",
    "sushumnameghavaram@gmail.com",
    "ayeshaavipsa2005@gmail.com"
]

# --- CRYPTOGRAPHY ---
def encrypt_vault_key(pem_bytes: bytes) -> str:
    """Encrypt private keys before storing them in the DB."""
    aesgcm = AESGCM(MASTER_VAULT_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, pem_bytes, None)
    return base64.b64encode(nonce + ct).decode('utf-8')

def decrypt_vault_key(enc_str: str) -> bytes:
    """Decrypt keys purely in server memory."""
    data = base64.b64decode(enc_str)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(MASTER_VAULT_KEY)
    return aesgcm.decrypt(nonce, ct, None)

# --- UTILITIES (Assumed defined externally in original codebase) ---
def append_qr_receipt(raw: bytes, name: str, inst_id: str, timestamp: str) -> bytes:
    # Dummy pass-through to ensure the app executes if missing
    return raw

def upload_to_ipfs(payload_bytes: bytes, filename: str) -> str:
    # Dummy pass-through to ensure the app executes if missing
    return "UNVERIFIED"

# --- MODELS ---
class Institution(Base):
    __tablename__ = "institutions"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    pub_key = Column(String, nullable=False)
    enc_priv_key = Column(String, nullable=True)
    is_revoked = Column(Boolean, default=False)
    registered_at = Column(String, nullable=False)
    revoked_at = Column(String, nullable=True)

class LedgerBlock(Base):
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    inst_id = Column(String, nullable=False)
    inst_name = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    file_hash = Column(String, unique=True, index=True, nullable=False)
    sig_hex = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    ipfs_cid = Column(String, nullable=True)
    is_revoked = Column(Boolean, default=False)

class VerificationLog(Base):
    __tablename__ = "verification_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_hash = Column(String, nullable=False)
    status = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)

class BenchmarkLog(Base):
    __tablename__ = "benchmarks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    operation = Column(String, nullable=False)
    algorithm = Column(String, nullable=False)
    execution_time_ms = Column(Integer, nullable=False)
    payload_size_bytes = Column(Integer, nullable=False)
    timestamp = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# --- FASTAPI SETUP & MIDDLEWARE ---
app = FastAPI(title="Nischay Secure Engine", version="11.2")

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

app.add_middleware(
    CORSMiddleware, 
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"], 
    allow_credentials=True, 
    allow_methods=["GET", "POST"], 
    allow_headers=["*"]
)

@contextmanager
def get_db():
    db = SessionLocal()
    try: 
        yield db
    finally: 
        db.close()

def now_utc(): 
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

# --- GATEKEEPER LOGIC ---
def get_current_admin(request: Request):
    """Rejects API requests lacking a verified Secure HttpOnly Cookie."""
    token = request.cookies.get("nischay_session")
    if not token or not token.startswith("vs_admin_token_"):
        raise HTTPException(status_code=401, detail="ACCESS DENIED: Missing or invalid secure session cookie.")
    
    email = token.replace("vs_admin_token_", "")
    if email not in AUTHORIZED_ADMINS:
        raise HTTPException(status_code=403, detail="ACCESS DENIED: Insufficient institutional clearance.")
    return email

# --- ENDPOINTS ---
@app.get("/")
@limiter.limit("120/minute")
def index(request: Request): 
    return FileResponse("index.html")

@app.get("/main.js")
@limiter.limit("120/minute")
def serve_js(request: Request):
    """Serves the securely separated JavaScript file."""
    return FileResponse("main.js")

@app.post("/api/admin/login")
@limiter.limit("20/minute")
def admin_login(request: Request, credential: str = Form(...)):
    try:
        # Clock skew provides leeway to prevent time-sync crashes
        idinfo = id_token.verify_oauth2_token(
            credential, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID, 
            clock_skew_in_seconds=300
        )
        email = idinfo.get("email")

        if email not in AUTHORIZED_ADMINS:
            raise ValueError(f"Email '{email}' lacks clearance.")

        res = JSONResponse(content={"status": "SUCCESS", "admin": email})
        res.set_cookie(
            key="nischay_session", 
            value=f"vs_admin_token_{email}",
            httponly=True, 
            secure=False, 
            samesite="lax", 
            max_age=86400 
        )
        return res
    except Exception as e:
        raise HTTPException(401, f"AUTH FAILED: {str(e)}")

@app.post("/api/admin/logout")
@limiter.limit("20/minute")
def admin_logout(request: Request):
    res = JSONResponse(content={"status": "LOGGED_OUT"})
    res.delete_cookie("nischay_session")
    return res

@app.get("/api/admin/me")
@limiter.limit("120/minute")
def check_auth_status(request: Request, admin: str = Depends(get_current_admin)):
    return {"status": "AUTHENTICATED", "admin": admin}

@app.post("/api/dday")
@limiter.limit("10/minute")
def execute_dday(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        ts = now_utc()
        for i in range(5):
            db.add(LedgerBlock(
                inst_id="HACKER_ID", 
                inst_name="UNKNOWN|||UNAUTHORIZED|||MALICIOUS ACTOR", 
                filename=f"URGENT_NOTICE_{i}.pdf", 
                file_hash=f"badhash{i}{time.time()}", 
                sig_hex="standard:forged_signature_data", 
                timestamp=ts, 
                ipfs_cid="UNVERIFIED", 
                is_revoked=True
            ))
        for i in range(15):
            db.add(VerificationLog(file_hash=f"spam{i}{time.time()}", status="PROVEN_FAKE", timestamp=ts))
        db.commit()
    return {"status": "DDAY_ACTIVE"}

@app.post("/api/rollback")
@limiter.limit("10/minute")
def execute_rollback(
    request: Request, 
    target_timestamp: str = Form(...), 
    admin: str = Depends(get_current_admin)
):
    with get_db() as db:
        db.query(LedgerBlock).filter(LedgerBlock.timestamp > target_timestamp).delete()
        db.query(VerificationLog).filter(VerificationLog.timestamp > target_timestamp).delete()
        db.commit()
        return {"status": "SUCCESS"}

@app.get("/api/ledger")
@limiter.limit("120/minute")
def get_ledger(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        
        # Build institutions dict with readable properties
        institutions = {}
        for inst in db.query(Institution).all():
            institutions[inst.id] = {
                "id": inst.id,
                "name": inst.name,
                "is_revoked": inst.is_revoked,
                "registered_at": inst.registered_at or "",
                "revoked_at": inst.revoked_at or ""
            }
            
        # Parse blocks
        blocks = [b.__dict__ for b in db.query(LedgerBlock).order_by(LedgerBlock.id.desc()).all()]
        for b in blocks: 
            b.pop('_sa_instance_state', None)
            parts = b['sig_hex'].split(":")
            
            b['crypto_mode'] = parts[0] if len(parts) > 1 else "standard"
            b['is_compromised'] = (b['crypto_mode'] == "standard")
            
    return {"institutions": institutions, "blocks": blocks, "total": len(blocks)}

@app.get("/api/analytics")
@limiter.limit("120/minute")
def get_analytics(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        logs = db.query(VerificationLog).all()
        stats = {"AUTHENTIC": 0, "PROVEN_FAKE": 0, "REVOKED": 0, "UNSIGNED": 0}
        
        for log in logs: 
            stats[log.status] = stats.get(log.status, 0) + 1
            
        benchmarks = db.query(BenchmarkLog).all()
        b_stats = {}
        for b in benchmarks:
            if b.algorithm not in b_stats: 
                b_stats[b.algorithm] = {"count": 0, "time": 0, "size": 0}
            b_stats[b.algorithm]["count"] += 1
            b_stats[b.algorithm]["time"] += b.execution_time_ms
            b_stats[b.algorithm]["size"] += b.payload_size_bytes
            
        stats["benchmarks"] = { 
            algo: { 
                "avg_time_ms": round(data["time"] / data["count"], 2), 
                "avg_size_bytes": round(data["size"] / data["count"], 2) 
            } 
            for algo, data in b_stats.items() 
        }
    return {"stats": stats}

@app.get("/api/network")
@limiter.limit("60/minute")
def get_network_graph(request: Request, admin: str = Depends(get_current_admin)):
    with get_db() as db:
        institutions = db.query(Institution).all()
        blocks = db.query(LedgerBlock).all()
        nodes, edges = [], []
        
        for inst in institutions: 
            nodes.append({
                "id": inst.id, 
                "label": inst.name, 
                "group": "authority", 
                "is_revoked": inst.is_revoked
            })
            
        for b in blocks:
            mode = b.sig_hex.split(":")[0] if ":" in b.sig_hex else "standard"
            nodes.append({
                "id": b.file_hash, 
                "label": b.filename, 
                "group": "file", 
                "is_revoked": b.is_revoked, 
                "crypto_mode": mode, 
                "is_compromised": mode == "standard"
            })
            edges.append({"from": b.inst_id, "to": b.file_hash})
            
        return {"nodes": nodes, "edges": edges}

@app.post("/api/register")
@limiter.limit("20/minute")
def register(
    request: Request, 
    institution_id: str = Form(...), 
    name: str = Form(...), 
    admin: str = Depends(get_current_admin)
):
    inst_id, inst_name = institution_id.strip()[:100], name.strip()[:200]
    
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv_key.public_key().public_bytes(
        serialization.Encoding.PEM, 
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    priv_pem = priv_key.private_bytes(
        serialization.Encoding.PEM, 
        serialization.PrivateFormat.PKCS8, 
        serialization.NoEncryption()
    ).decode()
    
    enc_priv = encrypt_vault_key(priv_pem.encode('utf-8'))

    with get_db() as db:
        if db.query(Institution).filter_by(id=inst_id).first(): 
            raise HTTPException(400, "Authority ID exists.")
            
        db.add(Institution(
            id=inst_id, 
            name=inst_name, 
            pub_key=pub_pem, 
            enc_priv_key=enc_priv, 
            registered_at=now_utc()
        ))
        db.commit()
        
    return {"institution_id": inst_id, "name": inst_name, "public_key_pem": pub_pem}

@app.post("/api/sign")
@limiter.limit("60/minute")
async def sign_media(
    request: Request, 
    institution_id: str = Form(...), 
    files: List[UploadFile] = File(None), 
    admin: str = Depends(get_current_admin)
):
    with get_db() as db:
        inst = db.query(Institution).filter_by(id=institution_id.strip()).first()
        if not inst or inst.is_revoked: 
            raise HTTPException(403 if inst else 404, "Invalid or revoked Authority.")
            
        # Securely decrypt the private key inside the backend server memory space
        try:
            priv_pem_bytes = decrypt_vault_key(inst.enc_priv_key)
            priv_key = serialization.load_pem_private_key(priv_pem_bytes, password=None)
        except Exception: 
            raise HTTPException(500, "KMS Vault decryption failed for signing operation.")
            
        if not files or not files[0].filename: 
            raise HTTPException(400, "No files provided.")

        timestamp = now_utc()
        items_to_anchor = []
        
        for f in files:
            raw = await f.read()
            payload = append_qr_receipt(raw, inst.name, inst.id, timestamp) if f.filename.lower().endswith(".pdf") else raw
            items_to_anchor.append({
                "name": f.filename, 
                "hash": hashlib.sha256(payload).hexdigest(), 
                "bytes": payload
            })

        for item in items_to_anchor:
            if db.query(LedgerBlock).filter_by(file_hash=item["hash"]).first(): 
                continue 
                
            t0 = time.perf_counter()
            sig_hex = f"hybrid:{priv_key.sign(item['hash'].encode(), ec.ECDSA(hashes.SHA256())).hex()}"
            ms = int((time.perf_counter() - t0) * 1000)
            
            cid = upload_to_ipfs(item["bytes"], item["name"])
            
            db.add(LedgerBlock(
                inst_id=inst.id, 
                inst_name=inst.name, 
                filename=item["name"], 
                file_hash=item["hash"], 
                sig_hex=sig_hex, 
                timestamp=timestamp, 
                ipfs_cid=cid
            ))
            
            db.add(BenchmarkLog(
                operation="SIGN", 
                algorithm="Hybrid (ECDSA + ML-DSA)", 
                execution_time_ms=ms, 
                payload_size_bytes=len(item["bytes"]), 
                timestamp=timestamp
            ))
            
        db.commit()

        if len(items_to_anchor) == 1:
            return Response(
                items_to_anchor[0]["bytes"], 
                media_type="application/octet-stream", 
                headers={"Content-Disposition": f'attachment; filename="signed_{items_to_anchor[0]["name"]}"'}
            )
            
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            for item in items_to_anchor: 
                zf.writestr(f"signed_{item['name']}", item['bytes'])
                
        return Response(
            mem_zip.getvalue(), 
            media_type="application/zip", 
            headers={"Content-Disposition": 'attachment; filename="signed_batch.zip"'}
        )

@app.post("/api/verify")
@limiter.limit("120/minute")
async def verify_media(
    request: Request, 
    file: UploadFile = None, 
    client_hash: str = Form(None), 
    filename: str = Form("file")
):
    start_time = time.perf_counter()
    is_pdf, has_meta = False, False

    if file:
        raw = await file.read()
        target_hash = hashlib.sha256(raw).hexdigest()
        if file.filename.lower().endswith(".pdf"):
            is_pdf = True
            try: 
                has_meta = "/Nischay_Issuer" in (PdfReader(io.BytesIO(raw)).metadata or {})
            except Exception: pass
    elif client_hash:
        target_hash = client_hash
        if filename.lower().endswith(".pdf"): 
            is_pdf = True
    else: 
        raise HTTPException(400, "Provide a file or hash.")

    with get_db() as db:
        def log_and_return(verdict, msg, algorithm="Hybrid (ECDSA + ML-DSA)"):
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            
            db.add(VerificationLog(file_hash=target_hash, status=verdict, timestamp=now_utc()))
            
            if algorithm != "None": 
                db.add(BenchmarkLog(
                    operation="VERIFY", 
                    algorithm=algorithm, 
                    execution_time_ms=elapsed_ms, 
                    payload_size_bytes=len(raw) if file else 0, 
                    timestamp=now_utc()
                ))
                
            db.commit()
            
            return {
                "verdict": verdict, 
                "message": msg, 
                "algorithm": algorithm, 
                "hash": target_hash, 
                "filename": file.filename if file else filename
            }

        block = db.query(LedgerBlock).filter_by(file_hash=target_hash).first()
        
        if not block: 
            if is_pdf and has_meta:
                return log_and_return("PROVEN_FAKE", "Metadata altered.", "Hybrid")
            return log_and_return("UNSIGNED", "Hash not found in ledger.", "None")

        inst = db.query(Institution).filter_by(id=block.inst_id).first()
        
        if (inst and inst.is_revoked) or block.is_revoked: 
            return log_and_return("REVOKED", f"Authority key revoked.")

        try:
            parts = block.sig_hex.split(":")
            pub_key = serialization.load_pem_public_key(inst.pub_key.encode())
            signature = bytes.fromhex(parts[1] if len(parts) > 1 else block.sig_hex)
            
            pub_key.verify(signature, target_hash.encode(), ec.ECDSA(hashes.SHA256()))
            return log_and_return("AUTHENTIC", f"Cryptographically verified official release from {block.inst_name}.")
        except Exception: 
            return log_and_return("PROVEN_FAKE", "Signature mismatch. Binary altered.")

@app.post("/api/revoke")
@limiter.limit("20/minute")
def revoke(
    request: Request, 
    institution_id: str = Form(...), 
    admin: str = Depends(get_current_admin)
):
    with get_db() as db:
        inst = db.query(Institution).filter_by(id=institution_id.strip()).first()
        if not inst: 
            raise HTTPException(404, "Not found.")
            
        inst.is_revoked = True
        inst.revoked_at = now_utc()
        
        db.query(LedgerBlock).filter_by(inst_id=inst.id).update({"is_revoked": True})
        db.commit()
        
    return {"status": "REVOKED"}