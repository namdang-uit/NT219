import base64
from fastapi import FastAPI
from pydantic import BaseModel
from pdf_signer import sign_pdf_bytes, verify_pdf_bytes

from crypto_core import generate_rsa_keypair, sha256, sign_digest, verify_digest

app = FastAPI(title="TSP Remote Signing Service (PoC)")

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

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/sign", response_model=SignResponse)
def sign(req: SignRequest):
    data = base64.b64decode(req.data_b64)
    digest = sha256(data)
    sig = sign_digest(KEYPAIR.private_key_pem, digest)
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
    return VerifyResponse(valid=ok)

class SignPdfRequest(BaseModel):
    pdf_b64: str

class SignPdfResponse(BaseModel):
    signed_pdf_b64: str

@app.post("/sign-pdf", response_model=SignPdfResponse)
def sign_pdf(req: SignPdfRequest):
    pdf_bytes = base64.b64decode(req.pdf_b64)
    signed = sign_pdf_bytes(pdf_bytes)
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
    return VerifyPdfResponse(all_valid=out["all_valid"], results=results)