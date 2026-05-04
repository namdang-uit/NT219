import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import requests
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from pdf_engine import sha256_digest

TSP_BASE_URL = os.getenv("TSP_BASE_URL", "http://localhost:8001")
TSP_TIMEOUT = float(os.getenv("TSP_TIMEOUT", "30"))
VERIFIER_BASE_URL = os.getenv("VERIFIER_BASE_URL")
VERIFIER_TIMEOUT = float(os.getenv("VERIFIER_TIMEOUT", "30"))
STORAGE_PATH = Path(os.getenv("STORAGE_PATH", "storage"))
AUDIT_LOG_PATH = Path(os.getenv("BACKEND_AUDIT_LOG_PATH", "/app/logs/backend_audit.jsonl"))

app = FastAPI(title="Public Backend API (PoC)")

class SignDigestResponse(BaseModel):
	digest_b64: str
	signature_b64: str
	public_key_pem_b64: str

class SignPdfResponse(SignDigestResponse):
	signed_pdf_b64: str
	file_id: str
	download_url: str

class VerifyPdfResult(BaseModel):
	field_name: str
	valid: bool
	trusted: bool
	summary: str

class VerifyPdfResponse(BaseModel):
	all_valid: bool
	results: list[VerifyPdfResult]

def _b64encode(data: bytes) -> str:
	return base64.b64encode(data).decode("ascii")


def _log_event(event: str, payload: dict[str, Any]) -> None:
	AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
	entry = {
		"ts": datetime.now(timezone.utc).isoformat(),
		"event": event,
		**payload,
	}
	with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
		handle.write(json.dumps(entry, ensure_ascii=True) + "\n")

def _post_json(path: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
	url = f"{TSP_BASE_URL}{path}"
	return _post_json_to_url(url, payload, timeout, "TSP")


def _post_json_to_url(
	url: str,
	payload: dict[str, Any],
	timeout: float,
	upstream_name: str,
) -> dict[str, Any]:
	try:
		resp = requests.post(url, json=payload, timeout=timeout)
	except requests.RequestException as exc:
		raise HTTPException(
			status_code=502, detail=f"{upstream_name} unreachable: {exc}"
		) from exc

	if resp.status_code >= 400:
		raise HTTPException(status_code=502, detail=f"TSP error: {resp.text}")

	return resp.json()


def _post_file_to_url(
	url: str,
	file_name: str,
	file_bytes: bytes,
	timeout: float,
	upstream_name: str,
) -> dict[str, Any]:
	files = {"file": (file_name or "document.pdf", file_bytes, "application/pdf")}
	try:
		resp = requests.post(url, files=files, timeout=timeout)
	except requests.RequestException as exc:
		raise HTTPException(
			status_code=502, detail=f"{upstream_name} unreachable: {exc}"
		) from exc

	if resp.status_code >= 400:
		raise HTTPException(status_code=502, detail=f"{upstream_name} error: {resp.text}")

	return resp.json()

def _validate_pdf_upload(file: UploadFile) -> None:
	if file.content_type in (None, "", "application/octet-stream"):
		return
	if file.content_type != "application/pdf":
		raise HTTPException(status_code=415, detail="Only PDF files are supported.")


def _ensure_storage_dir() -> None:
	STORAGE_PATH.mkdir(parents=True, exist_ok=True)


def _store_pdf(file_id: str, kind: str, data: bytes) -> Path:
	_ensure_storage_dir()
	path = STORAGE_PATH / f"{file_id}_{kind}.pdf"
	path.write_bytes(data)
	return path

@app.get("/health")
def health() -> dict[str, str]:
	return {"status": "ok"}

@app.post("/sign", response_model=SignDigestResponse)
def sign_pdf_hash(file: UploadFile = File(...)) -> SignDigestResponse:
	_validate_pdf_upload(file)
	pdf_bytes = file.file.read()
	if not pdf_bytes:
		raise HTTPException(status_code=400, detail="Empty upload.")

	digest = sha256_digest(pdf_bytes)
	digest_b64 = _b64encode(digest)

	_log_event(
		"sign_hash_requested",
		{"file_name": file.filename, "file_size": len(pdf_bytes), "digest_b64": digest_b64},
	)
	
	tsp_out = _post_json("/sign-digest", {"digest_b64": digest_b64}, TSP_TIMEOUT)
	return SignDigestResponse(
		digest_b64=digest_b64,
		signature_b64=tsp_out["signature_b64"],
		public_key_pem_b64=tsp_out["public_key_pem_b64"],
	)

@app.post("/sign-pdf", response_model=SignPdfResponse)
def sign_pdf(file: UploadFile = File(...)) -> SignPdfResponse:
	_validate_pdf_upload(file)
	pdf_bytes = file.file.read()
	if not pdf_bytes:
		raise HTTPException(status_code=400, detail="Empty upload.")

	digest = sha256_digest(pdf_bytes)
	digest_b64 = _b64encode(digest)

	_log_event(
		"sign_pdf_requested",
		{"file_name": file.filename, "file_size": len(pdf_bytes), "digest_b64": digest_b64},
	)

	tsp_sig = _post_json("/sign-digest", {"digest_b64": digest_b64}, TSP_TIMEOUT)
	tsp_pdf = _post_json("/sign-pdf", {"pdf_b64": _b64encode(pdf_bytes)}, 60)

	file_id = uuid4().hex
	_store_pdf(file_id, "original", pdf_bytes)
	signed_pdf_bytes = base64.b64decode(tsp_pdf["signed_pdf_b64"])
	_store_pdf(file_id, "signed", signed_pdf_bytes)

	response = SignPdfResponse(
		digest_b64=digest_b64,
		signature_b64=tsp_sig["signature_b64"],
		public_key_pem_b64=tsp_sig["public_key_pem_b64"],
		signed_pdf_b64=tsp_pdf["signed_pdf_b64"],
		file_id=file_id,
		download_url=f"/files/{file_id}",
	)
	_log_event(
		"sign_pdf_completed",
		{
			"file_id": file_id,
			"file_name": file.filename,
			"digest_b64": digest_b64,
		},
	)
	return response

@app.post("/verify-pdf", response_model=VerifyPdfResponse)
def verify_pdf(file: UploadFile = File(...)) -> VerifyPdfResponse:
	_validate_pdf_upload(file)
	pdf_bytes = file.file.read()
	if not pdf_bytes:
		raise HTTPException(status_code=400, detail="Empty upload.")
	
	if VERIFIER_BASE_URL:
		out = _post_file_to_url(
			f"{VERIFIER_BASE_URL}/verify-pdf",
			file.filename or "document.pdf",
			pdf_bytes,
			VERIFIER_TIMEOUT,
			"Verifier",
		)
	else:
		out = _post_json_to_url(
			f"{TSP_BASE_URL}/verify-pdf",
			{"pdf_b64": _b64encode(pdf_bytes)},
			60,
			"TSP",
		)
	results = [VerifyPdfResult(**r) for r in out.get("results", [])]
	response = VerifyPdfResponse(all_valid=bool(out.get("all_valid")), results=results)
	_log_event(
		"verify_pdf_requested",
		{"file_name": file.filename, "file_size": len(pdf_bytes), "all_valid": response.all_valid},
	)
	return response


@app.get("/files/{file_id}")
def download_signed_pdf(file_id: str) -> FileResponse:
	path = STORAGE_PATH / f"{file_id}_signed.pdf"
	if not path.is_file():
		raise HTTPException(status_code=404, detail="File not found.")
	return FileResponse(path, media_type="application/pdf", filename=f"{file_id}.pdf")
