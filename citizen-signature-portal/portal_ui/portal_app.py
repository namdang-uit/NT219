import base64
import os

import requests
import streamlit as st

BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "http://localhost:8000")
BACKEND_PUBLIC_URL = os.getenv("BACKEND_PUBLIC_URL")

st.title("Citizen Portal (PoC)")

uploaded = st.file_uploader("Upload PDF", type=["pdf"])


def _verify_pdf_bytes(pdf_bytes: bytes) -> dict:
    files = {"file": ("document.pdf", pdf_bytes, "application/pdf")}
    resp = requests.post(
        f"{BACKEND_BASE_URL}/verify-pdf",
        files=files,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def _fetch_stored_pdf(download_url: str) -> bytes:
    if download_url.startswith("http://") or download_url.startswith("https://"):
        url = download_url
    else:
        url = f"{BACKEND_BASE_URL.rstrip('/')}{download_url}"

    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.content


def _render_verify_result(out: dict) -> None:
    if not out.get("results"):
        st.warning("No signature fields found in this PDF")
        return

    if out.get("all_valid"):
        st.success("VALID PDF signature (integrity OK)")
    else:
        st.error("INVALID PDF signature")

    st.table(out["results"])

    if any(not r.get("trusted", False) for r in out["results"]):
        st.info("Note: 'trusted' can be false with self-signed certificates")

if st.button("Ping backend /health"):
    resp = requests.get(f"{BACKEND_BASE_URL}/health", timeout=5)
    resp.raise_for_status()
    st.success(resp.json())

if uploaded is not None:
    pdf_bytes = uploaded.getvalue()

    if st.button("Sign PDF"):
        files = {"file": (uploaded.name, pdf_bytes, "application/pdf")}
        resp = requests.post(
            f"{BACKEND_BASE_URL}/sign-pdf",
            files=files,
            timeout=60,
        )
        resp.raise_for_status()
        out = resp.json()

        st.session_state["signed_pdf_b64"] = out["signed_pdf_b64"]
        st.session_state["digest_b64"] = out["digest_b64"]
        st.session_state["signature_b64"] = out["signature_b64"]
        st.session_state["file_id"] = out.get("file_id")
        st.session_state["download_url"] = out.get("download_url")

        st.success("Signed!")

    if st.button("Verify uploaded PDF"):
        out = _verify_pdf_bytes(pdf_bytes)
        _render_verify_result(out)

    if "digest_b64" in st.session_state:
        st.subheader("Digest (base64)")
        st.code(st.session_state["digest_b64"], language="text")

    if "signature_b64" in st.session_state:
        st.subheader("Signature (base64)")
        st.code(st.session_state["signature_b64"], language="text")

    if "signed_pdf_b64" in st.session_state:
        signed_pdf = base64.b64decode(st.session_state["signed_pdf_b64"])
        st.download_button(
            "Download signed PDF",
            data=signed_pdf,
            file_name="signed.pdf",
            mime="application/pdf",
        )

        if st.button("Verify last signed PDF"):
            out = _verify_pdf_bytes(signed_pdf)
            _render_verify_result(out)

    if st.session_state.get("file_id"):
        st.subheader("Stored file")
        st.code(st.session_state["file_id"], language="text")

        download_url = st.session_state.get("download_url")
        if download_url and BACKEND_PUBLIC_URL:
            public_url = f"{BACKEND_PUBLIC_URL.rstrip('/')}{download_url}"
            st.link_button("Open stored PDF", public_url)

        if download_url:
            if st.button("Fetch stored PDF"):
                st.session_state["stored_pdf_bytes"] = _fetch_stored_pdf(download_url)

        if "stored_pdf_bytes" in st.session_state:
            st.download_button(
                "Download stored PDF",
                data=st.session_state["stored_pdf_bytes"],
                file_name=f"{st.session_state['file_id']}.pdf",
                mime="application/pdf",
            )