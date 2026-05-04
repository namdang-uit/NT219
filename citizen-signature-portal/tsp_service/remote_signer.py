from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from asn1crypto import algos
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils


DEFAULT_KEY_LABEL = "tsp-key"


@dataclass(frozen=True)
class HsmConfig:
    module_path: str
    token_label: str
    user_pin: str
    key_label: str


@dataclass(frozen=True)
class SignatureResult:
    signature: bytes
    public_key_pem: bytes


def load_hsm_config_from_env() -> Optional[HsmConfig]:
    module_path = os.getenv("PKCS11_MODULE")
    if not module_path:
        return None

    token_label = os.getenv("HSM_TOKEN_LABEL")
    user_pin = os.getenv("HSM_USER_PIN")
    key_label = os.getenv("HSM_KEY_LABEL", DEFAULT_KEY_LABEL)

    if not token_label or not user_pin:
        raise RuntimeError(
            "HSM_TOKEN_LABEL and HSM_USER_PIN are required when PKCS11_MODULE is set."
        )

    return HsmConfig(
        module_path=module_path,
        token_label=token_label,
        user_pin=user_pin,
        key_label=key_label,
    )


def _load_public_key_from_cert(cert_path: Path) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_public_key_pem(private_key_pem: Optional[bytes]) -> bytes:
    public_key_path = os.getenv("TSP_PUBLIC_KEY_PEM_PATH")
    if public_key_path:
        return Path(public_key_path).read_bytes()

    cert_path = os.getenv("TSP_CERT_PEM_PATH")
    if cert_path:
        return _load_public_key_from_cert(Path(cert_path))

    if private_key_pem is not None:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    raise RuntimeError(
        "Missing TSP_PUBLIC_KEY_PEM_PATH or TSP_CERT_PEM_PATH for public key export."
    )


def _load_private_key_pem_from_env() -> bytes:
    key_path = os.getenv("TSP_KEY_PEM_PATH")
    if not key_path:
        raise RuntimeError("TSP_KEY_PEM_PATH is required when HSM is not configured.")
    return Path(key_path).read_bytes()


def _sign_digest_with_pem(digest: bytes, private_key_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    return private_key.sign(
        digest,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )


def _sign_digest_with_hsm(digest: bytes, config: HsmConfig) -> bytes:
    try:
        from pkcs11 import KeyType, Mechanism, ObjectClass, lib
    except ImportError as exc:  # pragma: no cover - runtime dependency
        raise RuntimeError("python-pkcs11 is required for HSM signing.") from exc

    digest_info = algos.DigestInfo(
        {"digest_algorithm": {"algorithm": "sha256"}, "digest": digest}
    ).dump()

    pkcs11_lib = lib(config.module_path)
    tokens = list(pkcs11_lib.get_tokens(token_label=config.token_label))
    if not tokens:
        raise RuntimeError("No HSM token found with the configured label.")

    for token in tokens:
        try:
            with token.open(user_pin=config.user_pin) as session:
                private_key = session.get_key(
                    label=config.key_label,
                    key_type=KeyType.RSA,
                    object_class=ObjectClass.PRIVATE_KEY,
                )
                return private_key.sign(digest_info, mechanism=Mechanism.RSA_PKCS)
        except Exception:
            continue

    raise RuntimeError("No matching key found in tokens with the configured label.")


def sign_digest(digest: bytes) -> SignatureResult:
    config = load_hsm_config_from_env()
    if config:
        public_key_pem = _load_public_key_pem(private_key_pem=None)
        signature = _sign_digest_with_hsm(digest, config)
        return SignatureResult(signature=signature, public_key_pem=public_key_pem)

    private_key_pem = _load_private_key_pem_from_env()
    public_key_pem = _load_public_key_pem(private_key_pem)
    signature = _sign_digest_with_pem(digest, private_key_pem)
    return SignatureResult(signature=signature, public_key_pem=public_key_pem)
