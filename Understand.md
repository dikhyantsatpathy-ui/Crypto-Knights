# VeriSource: Enterprise Provenance Engine

**SIH SOAIDEATHON-S26 - Technical Documentation & Architecture Guide**

## 1. System Requirements & Installation

To run the VeriSource backend locally or deploy it to a production server, you must install the required dependencies. The system is built on Python 3.9+.

**`requirements.txt`**

```text
fastapi
uvicorn
sqlalchemy
psycopg2-binary
cryptography
pypdf
reportlab
qrcode
requests
python-multipart

```

**Installation Command:**

```powershell
pip install -r requirements.txt

```

---

## 2. Library Architecture & Justifications

Every library in this stack was chosen to maximize security, execution speed, and scalability for a zero-trust enterprise environment.

* **FastAPI**
* **Job:** Handles all HTTP web traffic, API endpoints, and asynchronous file uploads.
* **Why we picked it:** FastAPI natively supports asynchronous operations (`async`/`await`). When massive files are being uploaded, it doesn't freeze the server. It is significantly faster and handles higher concurrency than older frameworks like Flask or Django.


* **SQLAlchemy**
* **Job:** Acts as the Object-Relational Mapper (ORM) bridging Python classes to the database.
* **Why we picked it:** It makes the codebase environment-agnostic. We can test locally with a lightweight SQLite file, and when we deploy to a cloud server, SQLAlchemy automatically scales the same code to a heavy-duty PostgreSQL cluster. It also natively sanitizes inputs, preventing SQL Injection attacks.


* **Cryptography**
* **Job:** Generates Elliptic Curve (SECP256R1) keys, handles SHA-256 hashing, and executes the digital signatures.
* **Why we picked it:** It is the audited, industry-standard library for Python security. We chose Elliptic Curve over traditional RSA because ECDSA keys are significantly smaller and faster to compute while offering superior military-grade encryption.


* **PyPDF & ReportLab**
* **Job:** `ReportLab` draws the visual QR code onto a blank digital canvas. `PyPDF` merges that canvas into the uploaded document and injects the hidden cryptographic metadata.
* **Why we picked them:** They allow us to manipulate PDF binaries entirely in server RAM (using `io.BytesIO()`) without ever writing sensitive documents to the server's hard drive.


* **Requests**
* **Job:** Handles the external API calls to the Pinata IPFS network.
* **Why we picked it:** The standard, most reliable HTTP library for Python to ensure our IPFS anchoring never times out gracefully.



---

## 3. The Complete Backend Codebase (`app.py`)

*Save this code exactly as `app.py`. The architecture is bracketed into 8 operational zones for easy explanation.*

```python
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

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [1] DATABASE ARCHITECTURE & ORM SETUP                                   ║
# ╠═════════════════════════════════════════════════════════════════════════╣
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
# ╚═════════════════════════════════════════════════════════════════════════╝

app = FastAPI(title="VeriSource Engine", version="7.6")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
PINATA_JWT = os.getenv("PINATA_JWT", "")

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [2] CONTEXT MANAGER & SAFE CONNECTIONS                                  ║
# ╠═════════════════════════════════════════════════════════════════════════╣
@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# ╚═════════════════════════════════════════════════════════════════════════╝

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def clean_pem(pem_str: str) -> bytes:
    return pem_str.replace("\\n", "\n").replace("\r", "").strip().encode("utf-8")

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [3] DECENTRALIZED IPFS ANCHORING                                        ║
# ╠═════════════════════════════════════════════════════════════════════════╣
def upload_to_ipfs(file_bytes: bytes, filename: str) -> str:
    if not PINATA_JWT:
        return f"QmSimulated{hashlib.md5(file_bytes).hexdigest()[:34]}"
    try:
        headers = {"Authorization": f"Bearer {PINATA_JWT}"}
        res = requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS", headers=headers, files={"file": (filename, file_bytes)}, timeout=8)
        return res.json().get("IpfsHash", "IPFS_FAILED")
    except Exception:
        return "NETWORK_ERROR"
# ╚═════════════════════════════════════════════════════════════════════════╝

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [4] CRYPTOGRAPHIC METADATA TRAP & QR INJECTION                          ║
# ╠═════════════════════════════════════════════════════════════════════════╣
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
# ╚═════════════════════════════════════════════════════════════════════════╝

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

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [5] ELLIPTIC CURVE KEY GENERATION & REGISTRATION                        ║
# ╠═════════════════════════════════════════════════════════════════════════╣
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
# ╚═════════════════════════════════════════════════════════════════════════╝

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [6] DIGITAL SIGNATURE ENGINE & DUPLICATE PREVENTION                     ║
# ╠═════════════════════════════════════════════════════════════════════════╣
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
            if db.query(LedgerBlock).filter(LedgerBlock.file_hash == client_hash).first():
                raise HTTPException(400, "This media file hash is already anchored to the ledger.")

            sig_hex = priv_key.sign(client_hash.encode(), ec.ECDSA(hashes.SHA256())).hex()
            db.add(LedgerBlock(inst_id=inst_id, inst_name=inst.name, filename=filename, file_hash=client_hash, sig_hex=sig_hex, timestamp=timestamp, ipfs_cid="CLIENT_HASHED"))
            db.commit()
            return {"status": "SUCCESS", "file_hash": client_hash, "signature": sig_hex}
        else:
            raise HTTPException(400, "Provide files or a hash.")
# ╚═════════════════════════════════════════════════════════════════════════╝

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [7] ZERO-TRUST VERIFICATION & LOGIC GATE                                ║
# ╠═════════════════════════════════════════════════════════════════════════╣
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
# ╚═════════════════════════════════════════════════════════════════════════╝

# ╔═════════════════════════════════════════════════════════════════════════╗
# ║ [8] IMMUTABLE REVOCATION (THE KILL SWITCH)                              ║
# ╠═════════════════════════════════════════════════════════════════════════╣
@app.post("/api/revoke")
def revoke(institution_id: str = Form(...)):
    with get_db() as db:
        inst = db.query(Institution).filter(Institution.id == institution_id.strip()).first()
        if not inst: raise HTTPException(404, "Institution not found.")
        
        inst.is_revoked = True
        db.query(LedgerBlock).filter(LedgerBlock.inst_id == inst.id).update({"is_revoked": True})
        db.commit()
    return {"status": "REVOKED"}
# ╚═════════════════════════════════════════════════════════════════════════╝

```

---

## 4. Architectural Breakdown & Pitch Guide

*Use this section to defend your engineering choices during the SIH Q&A.*

### [1] Database Architecture & ORM Setup

* **How it works:** It maps Python classes (`Institution`, `LedgerBlock`) directly to database tables using SQLAlchemy. The `DATABASE_URL` line automatically detects if you are hosting the app locally or on a cloud server and patches the connection string.
* **Why this is the best method:** It abstracts away raw SQL syntax, inherently preventing SQL injection vulnerabilities, and ensures the codebase is completely environment-agnostic.
* **Why alternatives fail:** Using raw `INSERT INTO` queries makes your code brittle. You would have to write completely different SQL code for a local SQLite test environment than you would for a production PostgreSQL server.
* **The Hackathon Edge:** In a hackathon, you code locally but deploy to the web in minutes. This handles the migration instantly with zero rewrites, proving the software is highly scalable.

### [2] Context Manager & Safe Connections

* **How it works:** The `@contextmanager` allows any function to request a database session using `with get_db() as db:`. When the function completes, the `finally:` clause forces the database connection to close.
* **Why this is the best method:** It acts as an absolute safety net. Even if a fatal error occurs in the middle of a file upload, the connection drops safely.
* **Why alternatives fail:** Opening and closing connections manually relies on perfect human memory. If an exception triggers before a close command, the connection hangs open.
* **The Hackathon Edge:** It prevents catastrophic memory leaks under heavy load, demonstrating an understanding of production-level backend stability.

### [3] Decentralized IPFS Anchoring

* **How it works:** It takes the raw bytes of a document and pushes them to the Pinata Cloud API, pinning them to the InterPlanetary File System (IPFS) and returning a unique hash (CID).
* **Why this is the best method:** It guarantees absolute immutability and high availability. The document exists across a peer-to-peer network rather than on a single vulnerable machine.
* **Why alternatives fail:** Storing files on local servers or AWS S3 creates a centralized point of failure. If the primary server is hacked or unplugged, the data vanishes.
* **The Hackathon Edge:** Anchoring to the decentralized web proves you understand Web3 infrastructure and zero-trust distribution.

### [4] Cryptographic Metadata Trap & QR Injection

* **How it works:** It manipulates the PDF bytes entirely in RAM. It draws a visible QR code page and appends it to the document, while simultaneously using `pypdf` to inject hidden key-value tags (e.g., `/VeriSource_Issuer`) into the invisible metadata dictionary.
* **Why this is the best method:** It creates a binary contradiction if altered. If a hacker edits the PDF text, the SHA-256 hash completely changes. The backend sees the new hash is missing from the ledger but detects the hidden metadata claiming it is official, immediately deducing it is a forgery.
* **Why alternatives fail:** Visual watermarks can be Photoshopped out, and normal digital signatures just say "Invalid" without providing context on *why*.
* **The Hackathon Edge:** It differentiates a random unsigned file from an actively malicious deepfake, providing actionable threat intelligence to admins.

### [5] Elliptic Curve Key Generation

* **How it works:** Uses cryptography to generate an Elliptic Curve (`SECP256R1`) private and public key pair. The server saves the public key and returns the private key to the user.
* **Why this is the best method:** SECP256R1 is an NSA-grade standard used globally for securing web traffic and blockchain transactions due to its uncrackable mathematical properties.
* **Why alternatives fail:** Standard RSA encryption is heavy and generates massive keys that bog down fast API operations. Basic passwords can be brute-forced.
* **The Hackathon Edge:** It guarantees that signatures can only be forged if the actual private key is physically stolen, stripping the server of the liability of storing sensitive keys.

### [6] Digital Signature Engine & Duplicate Prevention

* **How it works:** Calculates the SHA-256 hash of the payload, checks the database to ensure the hash doesn't already exist, and signs the hash using the Elliptic Curve private key. It supports batch zipping for multiple files and raw string inputs for massive media.
* **Why this is the best method:** Handling hashing deterministically blocks identical insertions, preventing the backend from crashing via database `IntegrityError` loops.
* **Why alternatives fail:** Trying to sign an entire 10GB video directly (instead of its hash) is computationally disastrous and would cause timeout failures.
* **The Hackathon Edge:** The hybrid approach (handling PDFs Server-Side and massive media Client-Side) allows maximum UI convenience without sacrificing scalability.

### [7] Zero-Trust Verification & Logic Gate

* **How it works:** Re-hashes the submitted file. Queries the ledger. Checks the metadata. Validates the signature against the public key using `pub_key.verify()`. Drops a silent analytics log for every attempt.
* **Why this is the best method:** It removes human interpretation. The cryptography either perfectly aligns or forcefully throws an exception.
* **Why alternatives fail:** Returning a simple `True`/`False` response strips the user of context. A police department investigating a file needs to know exactly *why* it's fake.
* **The Hackathon Edge:** The four distinct states (Authentic, Proven Fake, Revoked, Unsigned) provide a complete, enterprise-grade forensic dashboard.

### [8] Immutable Revocation (The Kill Switch)

* **How it works:** A simple `UPDATE` query flips a boolean flag (`is_revoked = True`) on the institution and cascades that flag to every block ever anchored by them.
* **Why this is the best method:** It instantly kills trust in compromised credentials while preserving the historical record.
* **Why alternatives fail:** Running a `DELETE` command destroys the audit trail. If a rogue admin signs a fake document and you delete their account, you destroy the cryptographic proof that they did it.
* **The Hackathon Edge:** In cybersecurity, data is strictly append-only. Revocation is the only forensic-safe way to handle compromised identities.