from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from asn1crypto import pem, x509
from fastapi import FastAPI, File, HTTPException, UploadFile
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields
from pyhanko.sign.validation import EmbeddedPdfSignature, validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


TRUST_ROOT_PATH = Path(
    os.getenv("VERIFIER_TRUST_ROOT_PEM_PATH", "/app/certs/root_ca_cert.pem")
)
AUDIT_LOG_PATH = Path(os.getenv("VERIFIER_AUDIT_LOG_PATH", "/app/logs/verifier_audit.jsonl"))

app = FastAPI(title="Verifier Service (PoC)")


def _load_asn1crypto_cert(cert_pem: bytes) -> x509.Certificate:
    if pem.detect(cert_pem):
        _, _, der_bytes = pem.unarmor(cert_pem)
        return x509.Certificate.load(der_bytes)
    return x509.Certificate.load(cert_pem)


def verify_pdf_bytes(pdf_bytes: bytes) -> dict:
    trust_root_pem = TRUST_ROOT_PATH.read_bytes()
    trust_root = _load_asn1crypto_cert(trust_root_pem)
    vc = ValidationContext(trust_roots=[trust_root], allow_fetching=False)

    reader = PdfFileReader(BytesIO(pdf_bytes))

    results: list[dict] = []
    for field_name, _, field_ref in fields.enumerate_sig_fields(
        reader, filled_status=True
    ):
        embedded_sig = EmbeddedPdfSignature(reader, field_ref, field_name)
        status = validate_pdf_signature(embedded_sig, signer_validation_context=vc)
        results.append(
            {
                "field_name": field_name,
                "valid": bool(status.intact and status.valid),
                "trusted": bool(status.trusted),
                "summary": status.summary(),
            }
        )

    return {
        "all_valid": bool(results) and all(r["valid"] for r in results),
        "results": results,
    }


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
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/verify-pdf")
def verify_pdf(file: UploadFile = File(...)) -> dict:
    if file.content_type not in (None, "", "application/octet-stream", "application/pdf"):
        raise HTTPException(status_code=415, detail="Only PDF files are supported.")

    pdf_bytes = file.file.read()
    if not pdf_bytes:
        raise HTTPException(status_code=400, detail="Empty upload.")

    out = verify_pdf_bytes(pdf_bytes)
    _log_event(
        "verify_pdf_requested",
        {"file_name": file.filename, "file_size": len(pdf_bytes), "all_valid": out["all_valid"]},
    )
    return out
