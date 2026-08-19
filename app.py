import hashlib
import io
import os
import zipfile
import requests
import qrcode
from datetime import datetime, timezone
from typing import List
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from sqlalchemy import create_engine, Column, String, Integer, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------
# Database Architecture (Auto-scales to PostgreSQL)
# ---------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./provenance_ledger.db").replace("postgres://", "postgresql://", 1)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Institution(Base):
    __tablename__ = "institutions"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    pub_key = Column(String, nullable=False)
    is_revoked = Column(Boolean, default=False)
    registered_at = Column(String, nullable=False)

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

Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------
# Application Setup & Dependencies
# ---------------------------------------------------------
app = FastAPI(title="VeriSource Engine", version="7.6")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
PINATA_JWT = os.getenv("PINATA_JWT", "")

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def clean_pem(pem_str: str) -> bytes:
    return pem_str.replace("\\n", "\n").replace("\r", "").strip().encode("utf-8")

def upload_to_ipfs(file_bytes: bytes, filename: str) -> str:
    if not PINATA_JWT:
        return f"QmSimulated{hashlib.md5(file_bytes).hexdigest()[:34]}"
    try:
        headers = {"Authorization": f"Bearer {PINATA_JWT}"}
        res = requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS", headers=headers, files={"file": (filename, file_bytes)}, timeout=8)
        return res.json().get("IpfsHash", "IPFS_FAILED")
    except Exception:
        return "NETWORK_ERROR"

def append_qr_receipt(pdf_bytes: bytes, inst_name: str, inst_id: str, timestamp: str) -> bytes:
    qr_io = io.BytesIO()
    qrcode.make(f"VeriSource\nIssuer: {inst_name}\nID: {inst_id}\nTime: {timestamp}").save(qr_io, format="PNG")
    qr_io.seek(0)
    
    packet = io.BytesIO()
    c = canvas.Canvas(packet)
    c.drawString(100, 800, f"VeriSource Cryptographic Receipt - {inst_name}")
    c.drawImage(ImageReader(qr_io), 100, 600, width=150, height=150)
    c.save()
    packet.seek(0)
    
    writer = PdfWriter()
    main_pdf = PdfReader(io.BytesIO(pdf_bytes))
    for page in main_pdf.pages: 
        writer.add_page(page)
    writer.add_page(PdfReader(packet).pages[0])
    
    writer.add_metadata({
        "/VeriSource_Issuer": inst_name,
        "/VeriSource_IssuerID": inst_id,
        "/VeriSource_Timestamp": timestamp
    })
    
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()

# ---------------------------------------------------------
# Core API Routes
# ---------------------------------------------------------
@app.get("/")
def index():
    return FileResponse("index.html")

@app.get("/api/ledger")
def get_ledger():
    with get_db() as db:
        institutions = {i.id: {"id": i.id, "name": i.name, "is_revoked": i.is_revoked, "registered_at": i.registered_at} for i in db.query(Institution).all()}
        blocks = [{"id": b.id, "inst_id": b.inst_id, "inst_name": b.inst_name, "filename": b.filename, "file_hash": b.file_hash, "timestamp": b.timestamp, "ipfs_cid": b.ipfs_cid, "is_revoked": b.is_revoked} for b in db.query(LedgerBlock).order_by(LedgerBlock.id.desc()).all()]
    return {"institutions": institutions, "blocks": blocks, "total": len(blocks)}

@app.get("/api/analytics")
def get_analytics():
    with get_db() as db:
        logs = db.query(VerificationLog).all()
        stats = {"AUTHENTIC": 0, "PROVEN_FAKE": 0, "REVOKED": 0, "UNSIGNED": 0}
        for log in logs:
            if log.status in stats: stats[log.status] += 1
    return stats

@app.post("/api/register")
def register(institution_id: str = Form(...), name: str = Form(...)):
    inst_id, inst_name = institution_id.strip(), name.strip()
    
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    priv_pem = priv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

    with get_db() as db:
        if db.query(Institution).filter(Institution.id == inst_id).first():
            raise HTTPException(400, "Institution ID already exists.")
        db.add(Institution(id=inst_id, name=inst_name, pub_key=pub_pem, registered_at=now_utc()))
        db.commit()

    return {"institution_id": inst_id, "name": inst_name, "private_key_pem": priv_pem, "public_key_pem": pub_pem}

@app.post("/api/sign")
async def sign_media(
    institution_id: str = Form(...), 
    private_key_pem: str = Form(...), 
    files: List[UploadFile] = File(None),
    client_hash: str = Form(None),
    filename: str = Form("media_file")
):
    inst_id = institution_id.strip()
    
    with get_db() as db:
        inst = db.query(Institution).filter(Institution.id == inst_id).first()
        if not inst: raise HTTPException(404, "Institution not found.")
        if inst.is_revoked: raise HTTPException(403, "Credentials revoked.")

        try:
            priv_key = serialization.load_pem_private_key(clean_pem(private_key_pem), password=None)
        except Exception:
            raise HTTPException(400, "Invalid Private Key format.")

        timestamp = now_utc()
        processed_files = []
        
        if files and len(files) > 0 and files[0].filename != "":
            for file in files:
                raw_bytes = await file.read()
                final_filename = file.filename
                
                final_bytes = append_qr_receipt(raw_bytes, inst.name, inst_id, timestamp) if final_filename.lower().endswith(".pdf") else raw_bytes
                file_hash = hashlib.sha256(final_bytes).hexdigest()
                
                # Check for duplicate hash before anchoring
                if db.query(LedgerBlock).filter(LedgerBlock.file_hash == file_hash).first():
                    raise HTTPException(400, f"The file '{final_filename}' is already anchored to the ledger.")

                sig_hex = priv_key.sign(file_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()
                
                db.add(LedgerBlock(inst_id=inst_id, inst_name=inst.name, filename=final_filename, file_hash=file_hash, sig_hex=sig_hex, timestamp=timestamp, ipfs_cid=upload_to_ipfs(final_bytes, final_filename)))
                processed_files.append({"name": final_filename, "bytes": final_bytes, "hash": file_hash})
            
            db.commit()

            if len(processed_files) == 1:
                return Response(processed_files[0]["bytes"], media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="signed_{processed_files[0]["name"]}"', "X-File-Hash": processed_files[0]["hash"]})
            else:
                mem_zip = io.BytesIO()
                with zipfile.ZipFile(mem_zip, "w") as zf:
                    for pf in processed_files: zf.writestr(f"signed_{pf['name']}", pf['bytes'])
                mem_zip.seek(0)
                return Response(mem_zip.getvalue(), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="signed_batch.zip"'})
                
        elif client_hash:
            # Check for duplicate hash before anchoring
            if db.query(LedgerBlock).filter(LedgerBlock.file_hash == client_hash).first():
                raise HTTPException(400, "This media file hash is already anchored to the ledger.")

            sig_hex = priv_key.sign(client_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()
            db.add(LedgerBlock(inst_id=inst_id, inst_name=inst.name, filename=filename, file_hash=client_hash, sig_hex=sig_hex, timestamp=timestamp, ipfs_cid="CLIENT_HASHED"))
            db.commit()
            return {"status": "SUCCESS", "file_hash": client_hash, "signature": sig_hex}
        else:
            raise HTTPException(400, "Provide files or a hash.")

@app.post("/api/verify")
async def verify_media(file: UploadFile = None, client_hash: str = Form(None)):
    is_pdf, pdf_has_meta = False, False

    if file:
        file_bytes = await file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        if file.filename.lower().endswith(".pdf"):
            is_pdf = True
            try:
                if "/VeriSource_Issuer" in (PdfReader(io.BytesIO(file_bytes)).metadata or {}): 
                    pdf_has_meta = True
            except Exception: pass
    elif client_hash:
        file_hash = client_hash
    else:
        raise HTTPException(400, "Provide a file or hash.")

    with get_db() as db:
        def log_attempt(status_str):
            db.add(VerificationLog(file_hash=file_hash, status=status_str, timestamp=now_utc()))
            db.commit()

        block = db.query(LedgerBlock).filter(LedgerBlock.file_hash == file_hash).first()
        
        if not block:
            if is_pdf and pdf_has_meta:
                log_attempt("PROVEN_FAKE")
                return {"verdict": "PROVEN_FAKE", "message": "Hidden cryptographic metadata is present, but the hash has been altered and is missing from ledger. FORGERY DETECTED."}
            log_attempt("UNSIGNED")
            return {"verdict": "UNSIGNED", "message": "Hash not found. Unverified or unofficial file."}

        inst = db.query(Institution).filter(Institution.id == block.inst_id).first()
        if (inst and inst.is_revoked) or block.is_revoked:
            log_attempt("REVOKED")
            return {"verdict": "REVOKED", "message": f"Signed by {block.inst_name}, but key is REVOKED. Do not trust."}

        try:
            pub_key = serialization.load_pem_public_key(inst.pub_key.encode())
            pub_key.verify(bytes.fromhex(block.sig_hex), file_hash.encode(), ec.ECDSA(hashes.SHA256()))
            log_attempt("AUTHENTIC")
            return {"verdict": "AUTHENTIC", "message": f"Verified official release from {block.inst_name}.", "hash": file_hash}
        except Exception:
            log_attempt("PROVEN_FAKE")
            return {"verdict": "PROVEN_FAKE", "message": "Signature mismatch. Media payload maliciously altered."}

@app.post("/api/revoke")
def revoke(institution_id: str = Form(...)):
    with get_db() as db:
        inst = db.query(Institution).filter(Institution.id == institution_id.strip()).first()
        if not inst: raise HTTPException(404, "Institution not found.")
        
        inst.is_revoked = True
        db.query(LedgerBlock).filter(LedgerBlock.inst_id == inst.id).update({"is_revoked": True})
        db.commit()
    return {"status": "REVOKED"}