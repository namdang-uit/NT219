import os
import base64
import requests
import streamlit as st

TSP_BASE_URL = os.getenv("TSP_BASE_URL", "http://localhost:8001")

st.title("Citizen Portal (PoC)")

uploaded = st.file_uploader("Upload a file (PDF or any)", type=None)

col1, col2 = st.columns(2)

with col1:
    if st.button("Ping TSP /health"):
        r = requests.get(f"{TSP_BASE_URL}/health", timeout=5)
        st.success(r.json())

if uploaded is not None:
    data = uploaded.getvalue()
    data_b64 = base64.b64encode(data).decode()

    if st.button("Remote Sign (PoC)"):
        resp = requests.post(
            f"{TSP_BASE_URL}/sign",
            json={"data_b64": data_b64},
            timeout=30,
        )
        resp.raise_for_status()
        out = resp.json()

        st.session_state["signature_b64"] = out["signature_b64"]
        st.session_state["public_key_pem_b64"] = out["public_key_pem_b64"]
        st.success("Signed!")

        st.code(out["digest_b64"], language="text")

    if "signature_b64" in st.session_state:
        if st.button("Verify signature"):
            resp = requests.post(
                f"{TSP_BASE_URL}/verify",
                json={
                    "data_b64": data_b64,
                    "signature_b64": st.session_state["signature_b64"],
                    "public_key_pem_b64": st.session_state["public_key_pem_b64"],
                },
                timeout=30,
            )
            resp.raise_for_status()
            ok = resp.json()["valid"]
            if ok:
                st.success("VALID signature")
            else:
                st.error("INVALID signature (tampered or mismatch)")

    if st.button("Sign PDF (pyHanko)"):
        resp = requests.post(
            f"{TSP_BASE_URL}/sign-pdf",
            json={"pdf_b64": data_b64},
            timeout=60,
        )
        resp.raise_for_status()
        signed_b64 = resp.json()["signed_pdf_b64"]
        signed_pdf = base64.b64decode(signed_b64)

        st.success("PDF signed!")
        st.download_button(
            "Download signed PDF",
            data=signed_pdf,
            file_name="signed.pdf",
            mime="application/pdf",
        )