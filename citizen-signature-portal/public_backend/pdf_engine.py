import hashlib
from pathlib import Path
from typing import Optional, Tuple, Union

PdfPath = Union[str, Path]
PdfBox = Tuple[float, float, float, float]

DEFAULT_SIG_FIELD_NAME = "Signature1"
DEFAULT_SIG_BOX: PdfBox = (50, 50, 250, 120)

def _as_existing_path(pdf_path: PdfPath) -> Path:
    path = Path(pdf_path)
    if not path.is_file():
        raise FileNotFoundError(f"PDF not found: {path}")
    return path

def read_pdf_bytes(pdf_path: PdfPath) -> bytes:
    path = _as_existing_path(pdf_path)
    with path.open("rb") as handle:
        return handle.read()

def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hash_pdf_sha256_hex(pdf_path: PdfPath) -> str:
    return sha256_hex(read_pdf_bytes(pdf_path))

def add_empty_signature_field(
    input_pdf: PdfPath,
    output_pdf: PdfPath,
    field_name: str = DEFAULT_SIG_FIELD_NAME,
    box: Optional[PdfBox] = DEFAULT_SIG_BOX,
    page_index: int = 0,
) -> None:
    
    try:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import fields
    except ImportError as exc:
        raise RuntimeError(
            "pyHanko is required for adding signature fields. "
            "Install it in the backend environment."
        ) from exc

    in_path = _as_existing_path(input_pdf)
    out_path = Path(output_pdf)

    with in_path.open("rb") as inf:
        writer = IncrementalPdfFileWriter(inf)
        spec = fields.SigFieldSpec(
            sig_field_name=field_name,
            box=box,
            on_page=page_index,
        )
        fields.append_signature_field(writer, spec)
        with out_path.open("wb") as outf:
            writer.write(outf)
