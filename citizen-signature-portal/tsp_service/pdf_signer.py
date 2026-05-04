from __future__ import annotations

import inspect
import os
from io import BytesIO
from pathlib import Path

from asn1crypto import keys, pem, x509

from pyhanko.sign import fields
from pyhanko.sign import signers
from pyhanko.sign import timestamps
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers.pdf_signer import PdfSigner
from pyhanko.sign.validation import EmbeddedPdfSignature, validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore


DEFAULT_CERT_PATH = Path(__file__).parent / "certs" / "signer.crt"
DEFAULT_KEY_PATH = Path(__file__).parent / "certs" / "signer.key"
PDF_SIGNING_MODE = os.getenv("PDF_SIGNING_MODE", "pem").lower()


def _resolve_path(env_var: str, default: Path) -> Path:
    return Path(os.getenv(env_var, str(default)))


def _get_signing_paths() -> tuple[Path, Path]:
    cert_path = _resolve_path("TSP_CERT_PEM_PATH", DEFAULT_CERT_PATH)
    key_path = _resolve_path("TSP_KEY_PEM_PATH", DEFAULT_KEY_PATH)
    return cert_path, key_path


def _get_trust_root_path() -> Path:
    trust_path = os.getenv("TSP_TRUSTED_ROOT_PEM_PATH")
    if trust_path:
        return Path(trust_path)
    cert_path = os.getenv("TSP_CERT_PEM_PATH")
    if cert_path:
        return Path(cert_path)
    return DEFAULT_CERT_PATH


def _build_validation_context() -> ValidationContext:
    trust_root_pem = _get_trust_root_path().read_bytes()
    trust_root = _load_asn1crypto_cert_from_pem_bytes(trust_root_pem)
    return ValidationContext(trust_roots=[trust_root], allow_fetching=False)


def _validation_context_param() -> str | None:
    params = inspect.signature(PdfSigner.sign_pdf).parameters
    if "validation_context" in params:
        return "validation_context"
    if "validation_contexts" in params:
        return "validation_contexts"
    return None


def _build_timestamper() -> timestamps.TimeStamper | None:
    tsa_url = os.getenv("TSA_URL")
    if not tsa_url:
        return None
    return timestamps.HTTPTimeStamper(tsa_url)


def _build_cert_store(cert: x509.Certificate) -> SimpleCertificateStore:
    store = SimpleCertificateStore()
    store.register(cert)
    return store


def _build_pem_signer(cert: x509.Certificate, key_pem: bytes) -> signers.SimpleSigner:
    if pem.detect(key_pem):
        _, _, key_der = pem.unarmor(key_pem)
        signing_key = keys.PrivateKeyInfo.load(key_der)
    else:
        signing_key = keys.PrivateKeyInfo.load(key_pem)

    return signers.SimpleSigner(
        signing_cert=cert,
        signing_key=signing_key,
        cert_registry=_build_cert_store(cert),
    )


def _build_pkcs11_signer(cert: x509.Certificate) -> signers.Signer:
    try:
        from pyhanko.sign.signers import pkcs11 as pkcs11_signers
        from pkcs11 import lib as pkcs11_lib
    except ImportError as exc:  # pragma: no cover - runtime dependency
        raise RuntimeError("pyHanko PKCS#11 support is required for HSM PDF signing.") from exc

    pkcs11_module = os.getenv("PKCS11_MODULE")
    token_label = os.getenv("HSM_TOKEN_LABEL")
    user_pin = os.getenv("HSM_USER_PIN")
    key_label = os.getenv("HSM_KEY_LABEL")

    if not pkcs11_module or not token_label or not user_pin or not key_label:
        raise RuntimeError("Missing PKCS#11 environment variables for HSM PDF signing.")

    signer_cls = pkcs11_signers.PKCS11Signer
    params = inspect.signature(signer_cls).parameters
    kwargs: dict[str, object] = {}

    if "pkcs11_module" in params:
        kwargs["pkcs11_module"] = pkcs11_module
    if "pkcs11_lib" in params:
        kwargs["pkcs11_lib"] = pkcs11_lib(pkcs11_module)
    if "token_label" in params:
        kwargs["token_label"] = token_label
    if "token" in params:
        kwargs["token"] = token_label
    if "user_pin" in params:
        kwargs["user_pin"] = user_pin
    if "pin" in params:
        kwargs["pin"] = user_pin
    if "key_label" in params:
        kwargs["key_label"] = key_label
    if "label" in params:
        kwargs["label"] = key_label
    if "signing_cert" in params:
        kwargs["signing_cert"] = cert
    if "cert" in params:
        kwargs["cert"] = cert
    if "cert_registry" in params:
        kwargs["cert_registry"] = _build_cert_store(cert)
    if "other_certs" in params:
        kwargs["other_certs"] = []
    if "cert_chain" in params:
        kwargs["cert_chain"] = []

    return signer_cls(**kwargs)


def _load_asn1crypto_cert_from_pem_bytes(cert_pem: bytes) -> x509.Certificate:
    # cert_pem can be PEM or DER; handle both
    if pem.detect(cert_pem):
        _, _, der_bytes = pem.unarmor(cert_pem)
        return x509.Certificate.load(der_bytes)
    return x509.Certificate.load(cert_pem)


def sign_pdf_bytes(pdf_bytes: bytes) -> bytes:
    cert_path, key_path = _get_signing_paths()
    cert_pem = cert_path.read_bytes()
    key_pem = key_path.read_bytes()

    cert = _load_asn1crypto_cert_from_pem_bytes(cert_pem)

    if PDF_SIGNING_MODE == "hsm":
        try:
            signer = _build_pkcs11_signer(cert)
        except Exception:
            signer = _build_pem_signer(cert, key_pem)
    else:
        signer = _build_pem_signer(cert, key_pem)

    embed_validation_requested = bool(os.getenv("EMBED_VALIDATION_INFO"))
    validation_param = _validation_context_param()
    embed_validation = embed_validation_requested and validation_param is not None

    meta = signers.PdfSignatureMetadata(
        field_name="Signature1",
        embed_validation_info=embed_validation,
    )
    pdf_signer = PdfSigner(
        signature_meta=meta,
        signer=signer,
        new_field_spec=SigFieldSpec("Signature1"),
    )

    in_buf = BytesIO(pdf_bytes)
    writer = IncrementalPdfFileWriter(in_buf)

    out_buf = BytesIO()
    sign_kwargs: dict[str, object] = {}
    timestamper = _build_timestamper()
    if timestamper is not None:
        if "timestamper" in inspect.signature(pdf_signer.sign_pdf).parameters:
            sign_kwargs["timestamper"] = timestamper

    if embed_validation and validation_param:
        sign_kwargs[validation_param] = _build_validation_context()

    pdf_signer.sign_pdf(writer, output=out_buf, **sign_kwargs)
    return out_buf.getvalue()


def verify_pdf_bytes(pdf_bytes: bytes) -> dict:
    trust_root_pem = _get_trust_root_path().read_bytes()
    trust_root = _load_asn1crypto_cert_from_pem_bytes(trust_root_pem)
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