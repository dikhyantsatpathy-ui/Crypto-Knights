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

NEON_DB_URL = "postgresql://neondb_owner:npg_PHMKh6Vtlw8f@ep-red-scene-azg0qzq0.c-3.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"
DATABASE_URL = os.getenv("DATABASE_URL", NEON_DB_URL).replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Models ---
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

# --- App Config ---
app = FastAPI(title="VeriSource Engine", version="8.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
PINATA_JWT = os.getenv("PINATA_JWT", "")

# --- Utils ---
@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def now_utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def clean_pem(pem_str: str) -> bytes:
    return pem_str.replace("\\n", "\n").replace("\r", "").strip().encode("utf-8")

def upload_to_ipfs(file_bytes: bytes, filename: str) -> str:
    if not PINATA_JWT: return f"QmSimulated{hashlib.md5(file_bytes).hexdigest()[:34]}"
    try:
        res = requests.post(
            "https://api.pinata.cloud/pinning/pinFileToIPFS", 
            headers={"Authorization": f"Bearer {PINATA_JWT}"}, 
            files={"file": (filename, file_bytes)}, timeout=8
        )
        return res.json().get("IpfsHash", "IPFS_FAILED")
    except Exception:
        return "NETWORK_ERROR"

def append_qr_receipt(pdf_bytes: bytes, inst_name: str, inst_id: str, timestamp: str) -> bytes:
    # Generate the visual QR code
    qr_io = io.BytesIO()
    qrcode.make(f"VeriSource\nIssuer: {inst_name}\nID: {inst_id}\nTime: {timestamp}").save(qr_io, format="PNG")
    qr_io.seek(0)
    
    # Draw the QR onto a blank PDF canvas
    packet = io.BytesIO()
    c = canvas.Canvas(packet)
    c.drawString(100, 800, f"VeriSource Cryptographic Receipt - {inst_name}")
    c.drawImage(ImageReader(qr_io), 100, 600, width=150, height=150)
    c.save()
    packet.seek(0)
    
    # Merge canvas with original PDF
    writer = PdfWriter()
    main_pdf = PdfReader(io.BytesIO(pdf_bytes))
    for page in main_pdf.pages: writer.add_page(page)
    writer.add_page(PdfReader(packet).pages[0])
    
    # Inject hidden forensic metadata
    writer.add_metadata({"/VeriSource_Issuer": inst_name, "/VeriSource_IssuerID": inst_id, "/VeriSource_Timestamp": timestamp})
    
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()

# --- API Routes ---
@app.get("/")
def index():
    return FileResponse("index.html")

@app.get("/api/ledger")
def get_ledger():
    with get_db() as db:
        institutions = {i.id: {"id": i.id, "name": i.name, "is_revoked": i.is_revoked} for i in db.query(Institution).all()}
        blocks = [b.__dict__ for b in db.query(LedgerBlock).order_by(LedgerBlock.id.desc()).all()]
        for b in blocks: b.pop('_sa_instance_state', None) # Clean SQLAlchemy internals before sending to frontend
    return {"institutions": institutions, "blocks": blocks, "total": len(blocks)}

@app.get("/api/analytics")
def get_analytics():
    with get_db() as db:
        logs = db.query(VerificationLog).all()
        stats = {"AUTHENTIC": 0, "PROVEN_FAKE": 0, "REVOKED": 0, "UNSIGNED": 0}
        for log in logs: stats[log.status] = stats.get(log.status, 0) + 1
    return stats

@app.post("/api/register")
def register(institution_id: str = Form(...), name: str = Form(...)):
    inst_id, inst_name = institution_id.strip(), name.strip()
    
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    priv_pem = priv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

    with get_db() as db:
        if db.query(Institution).filter_by(id=inst_id).first():
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
    with get_db() as db:
        inst = db.query(Institution).filter_by(id=institution_id.strip()).first()
        if not inst or inst.is_revoked:
            raise HTTPException(403 if inst else 404, "Invalid or revoked institution.")

        try:
            priv_key = serialization.load_pem_private_key(clean_pem(private_key_pem), password=None)
        except Exception:
            raise HTTPException(400, "Invalid Private Key format.")

        timestamp = now_utc()
        items_to_anchor = []

        # 1. Parse inputs: Are we hashing heavy media locally or processing standard files server-side?
        if client_hash:
            items_to_anchor.append({"name": filename, "hash": client_hash, "bytes": None, "ipfs": "CLIENT_HASHED"})
        elif files and files[0].filename:
            for f in files:
                raw = await f.read()
                # Inject QR/Metadata if it's a PDF, otherwise leave bytes untouched to preserve evidence
                payload = append_qr_receipt(raw, inst.name, inst.id, timestamp) if f.filename.lower().endswith(".pdf") else raw
                items_to_anchor.append({"name": f.filename, "hash": hashlib.sha256(payload).hexdigest(), "bytes": payload, "ipfs": None})
        else:
            raise HTTPException(400, "Provide files or a client hash.")

        # 2. Anchor payload to the ledger
        for item in items_to_anchor:
            if db.query(LedgerBlock).filter_by(file_hash=item["hash"]).first():
                raise HTTPException(400, f"Hash for '{item['name']}' already exists on ledger.")

            sig_hex = priv_key.sign(item["hash"].encode(), ec.ECDSA(hashes.SHA256())).hex()
            cid = item["ipfs"] or upload_to_ipfs(item["bytes"], item["name"])
            
            db.add(LedgerBlock(inst_id=inst.id, inst_name=inst.name, filename=item["name"], file_hash=item["hash"], sig_hex=sig_hex, timestamp=timestamp, ipfs_cid=cid))
        db.commit()

        # 3. Handle specific responses (Client Hash -> JSON, Single File -> Download, Batch -> ZIP)
        if client_hash:
            return {"status": "SUCCESS", "file_hash": client_hash}
        elif len(items_to_anchor) == 1:
            return Response(items_to_anchor[0]["bytes"], media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="signed_{items_to_anchor[0]["name"]}"'})
        else:
            mem_zip = io.BytesIO()
            with zipfile.ZipFile(mem_zip, "w") as zf:
                for item in items_to_anchor: zf.writestr(f"signed_{item['name']}", item['bytes'])
            return Response(mem_zip.getvalue(), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="signed_batch.zip"'})

@app.post("/api/verify")
async def verify_media(file: UploadFile = None, client_hash: str = Form(None)):
    is_pdf, has_meta = False, False

    # Extract hash and identify deepfake trap metadata
    if file:
        raw = await file.read()
        target_hash = hashlib.sha256(raw).hexdigest()
        if file.filename.lower().endswith(".pdf"):
            is_pdf = True
            try: has_meta = "/VeriSource_Issuer" in (PdfReader(io.BytesIO(raw)).metadata or {})
            except Exception: pass
    elif client_hash:
        target_hash = client_hash
    else:
        raise HTTPException(400, "Provide a file or hash.")

    with get_db() as db:
        # Helper function to dry out repetitive logging and returning
        def log_and_return(verdict, msg):
            db.add(VerificationLog(file_hash=target_hash, status=verdict, timestamp=now_utc()))
            db.commit()
            return {"verdict": verdict, "message": msg}

        block = db.query(LedgerBlock).filter_by(file_hash=target_hash).first()
        
        if not block:
            if is_pdf and has_meta:
                return log_and_return("PROVEN_FAKE", "Metadata trap triggered. File has been actively forged.")
            return log_and_return("UNSIGNED", "Hash not found. Unverified or unofficial file.")

        inst = db.query(Institution).filter_by(id=block.inst_id).first()
        if (inst and inst.is_revoked) or block.is_revoked:
            return log_and_return("REVOKED", f"Signed by {block.inst_name}, but key is REVOKED.")

        try:
            pub_key = serialization.load_pem_public_key(inst.pub_key.encode())
            pub_key.verify(bytes.fromhex(block.sig_hex), target_hash.encode(), ec.ECDSA(hashes.SHA256()))
            return log_and_return("AUTHENTIC", f"Verified official release from {block.inst_name}.")
        except Exception:
            return log_and_return("PROVEN_FAKE", "Signature mismatch. Payload altered.")

@app.post("/api/revoke")
def revoke(institution_id: str = Form(...)):
    with get_db() as db:
        inst = db.query(Institution).filter_by(id=institution_id.strip()).first()
        if not inst: raise HTTPException(404, "Institution not found.")
        
        inst.is_revoked = True
        db.query(LedgerBlock).filter_by(inst_id=inst.id).update({"is_revoked": True})
        db.commit()
    return {"status": "REVOKED"}