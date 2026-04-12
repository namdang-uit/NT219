from __future__ import annotations

from io import BytesIO
from pathlib import Path

from asn1crypto import keys, pem, x509

from pyhanko.sign import fields
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers.pdf_signer import PdfSigner
from pyhanko.sign.validation import EmbeddedPdfSignature, validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore


CERT_PATH = Path(__file__).parent / "certs" / "signer.crt"
KEY_PATH = Path(__file__).parent / "certs" / "signer.key"


def _load_asn1crypto_cert_from_pem_bytes(cert_pem: bytes) -> x509.Certificate:
    # cert_pem can be PEM or DER; handle both
    if pem.detect(cert_pem):
        _, _, der_bytes = pem.unarmor(cert_pem)
        return x509.Certificate.load(der_bytes)
    return x509.Certificate.load(cert_pem)


def sign_pdf_bytes(pdf_bytes: bytes) -> bytes:
    cert_pem = CERT_PATH.read_bytes()
    key_pem = KEY_PATH.read_bytes()

    cert = _load_asn1crypto_cert_from_pem_bytes(cert_pem)

    if pem.detect(key_pem):
        _, _, key_der = pem.unarmor(key_pem)
        signing_key = keys.PrivateKeyInfo.load(key_der)
    else:
        signing_key = keys.PrivateKeyInfo.load(key_pem)

    store = SimpleCertificateStore()
    store.register(cert)

    simple_signer = signers.SimpleSigner(
        signing_cert=cert,
        signing_key=signing_key,
        cert_registry=store,
    )

    meta = signers.PdfSignatureMetadata(field_name="Signature1")
    pdf_signer = PdfSigner(
        signature_meta=meta,
        signer=simple_signer,
        new_field_spec=SigFieldSpec("Signature1"),
    )

    in_buf = BytesIO(pdf_bytes)
    writer = IncrementalPdfFileWriter(in_buf)

    out_buf = BytesIO()
    pdf_signer.sign_pdf(writer, output=out_buf)
    return out_buf.getvalue()


def verify_pdf_bytes(pdf_bytes: bytes) -> dict:
    cert_pem = CERT_PATH.read_bytes()
    trust_root = _load_asn1crypto_cert_from_pem_bytes(cert_pem)
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