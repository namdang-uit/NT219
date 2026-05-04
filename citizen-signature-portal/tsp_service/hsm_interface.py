"""Backward compatible wrapper for remote_signer."""

from remote_signer import (  # noqa: F401
    DEFAULT_KEY_LABEL,
    HsmConfig,
    SignatureResult,
    load_hsm_config_from_env,
    sign_digest,
)

__all__ = [
    "DEFAULT_KEY_LABEL",
    "HsmConfig",
    "SignatureResult",
    "load_hsm_config_from_env",
    "sign_digest",
]
