import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel
from pdf_signer import sign_pdf_bytes, verify_pdf_bytes

from crypto_core import generate_rsa_keypair, sha256, sign_digest, verify_digest
from remote_signer import sign_digest as hsm_sign_digest

app = FastAPI(title="TSP Remote Signing Service (PoC)")

AUDIT_LOG_PATH = Path(os.getenv("TSP_AUDIT_LOG_PATH", "/app/logs/tsp_audit.jsonl"))

# PoC: generate one server key at startup (midterm OK).
KEYPAIR = generate_rsa_keypair()

class SignRequest(BaseModel):
    data_b64: str  # file bytes (base64)

class SignResponse(BaseModel):
    digest_b64: str
    signature_b64: str
    public_key_pem_b64: str

class VerifyRequest(BaseModel):
    data_b64: str
    signature_b64: str
    public_key_pem_b64: str

class VerifyResponse(BaseModel):
    valid: bool


class SignDigestRequest(BaseModel):
    digest_b64: str


class SignDigestResponse(BaseModel):
    signature_b64: str
    public_key_pem_b64: str


def _log_event(event: str, payload: dict) -> None:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **payload,
    }
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/sign", response_model=SignResponse)
def sign(req: SignRequest):
    data = base64.b64decode(req.data_b64)
    digest = sha256(data)
    sig = sign_digest(KEYPAIR.private_key_pem, digest)
    _log_event("sign_requested", {"data_size": len(data)})
    return SignResponse(
        digest_b64=base64.b64encode(digest).decode(),
        signature_b64=base64.b64encode(sig).decode(),
        public_key_pem_b64=base64.b64encode(KEYPAIR.public_key_pem).decode(),
    )

@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    data = base64.b64decode(req.data_b64)
    sig = base64.b64decode(req.signature_b64)
    pub = base64.b64decode(req.public_key_pem_b64)

    digest = sha256(data)
    ok = verify_digest(pub, digest, sig)
    _log_event("verify_requested", {"data_size": len(data), "valid": ok})
    return VerifyResponse(valid=ok)


@app.post("/sign-digest", response_model=SignDigestResponse)
def sign_digest_endpoint(req: SignDigestRequest):
    digest = base64.b64decode(req.digest_b64)
    result = hsm_sign_digest(digest)
    _log_event("sign_digest_requested", {"digest_b64": req.digest_b64})
    return SignDigestResponse(
        signature_b64=base64.b64encode(result.signature).decode(),
        public_key_pem_b64=base64.b64encode(result.public_key_pem).decode(),
    )

class SignPdfRequest(BaseModel):
    pdf_b64: str

class SignPdfResponse(BaseModel):
    signed_pdf_b64: str

@app.post("/sign-pdf", response_model=SignPdfResponse)
def sign_pdf(req: SignPdfRequest):
    pdf_bytes = base64.b64decode(req.pdf_b64)
    signed = sign_pdf_bytes(pdf_bytes)
    _log_event("sign_pdf_requested", {"data_size": len(pdf_bytes)})
    return SignPdfResponse(signed_pdf_b64=base64.b64encode(signed).decode())


class VerifyPdfRequest(BaseModel):
    pdf_b64: str


class VerifyPdfResult(BaseModel):
    field_name: str
    valid: bool
    trusted: bool
    summary: str


class VerifyPdfResponse(BaseModel):
    all_valid: bool
    results: list[VerifyPdfResult]


@app.post("/verify-pdf", response_model=VerifyPdfResponse)
def verify_pdf(req: VerifyPdfRequest):
    pdf_bytes = base64.b64decode(req.pdf_b64)
    out = verify_pdf_bytes(pdf_bytes)
    results = [VerifyPdfResult(**r) for r in out["results"]]
    _log_event("verify_pdf_requested", {"data_size": len(pdf_bytes), "all_valid": out["all_valid"]})
    return VerifyPdfResponse(all_valid=out["all_valid"], results=results)