#!/bin/sh
set -eu

if [ -z "${PKCS11_MODULE:-}" ]; then
  if [ -f "/usr/lib/softhsm/libsofthsm2.so" ]; then
    PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
  elif [ -f "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" ]; then
    PKCS11_MODULE="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
  fi
  export PKCS11_MODULE
fi

if [ -n "${PKCS11_MODULE:-}" ]; then
  HSM_TOKEN_LABEL=${HSM_TOKEN_LABEL:-tsp-token}
  HSM_USER_PIN=${HSM_USER_PIN:-1234}
  HSM_SO_PIN=${HSM_SO_PIN:-0000}
  HSM_KEY_LABEL=${HSM_KEY_LABEL:-tsp-key}
  TSP_KEY_PEM_PATH=${TSP_KEY_PEM_PATH:-/app/certs/tsp_key.pem}
  KEY_MARKER=/app/softhsm/.key_imported
  PKCS8_KEY_PATH=/app/softhsm/tsp_key.pk8

  export SOFTHSM2_CONF=${SOFTHSM2_CONF:-/app/softhsm2.conf}

  mkdir -p /app/softhsm/tokens
  if [ ! -f "$SOFTHSM2_CONF" ]; then
    cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = /app/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF
  fi

  token_count=$(softhsm2-util --show-slots | grep -c "Label: $HSM_TOKEN_LABEL" || true)
  if [ "$token_count" -eq 0 ]; then
    softhsm2-util --init-token --free --label "$HSM_TOKEN_LABEL" --pin "$HSM_USER_PIN" --so-pin "$HSM_SO_PIN"
  elif [ "$token_count" -gt 1 ]; then
    echo "Multiple SoftHSM tokens with label '$HSM_TOKEN_LABEL' detected."
    echo "Delete the softhsm_tokens volume and restart."
    exit 1
  fi

  if [ ! -f "$KEY_MARKER" ]; then
    if ! command -v openssl >/dev/null 2>&1; then
      echo "openssl is required to convert PEM key to PKCS#8 for SoftHSM import."
      exit 1
    fi

    openssl pkcs8 -topk8 -nocrypt -in "$TSP_KEY_PEM_PATH" -out "$PKCS8_KEY_PATH"
    softhsm2-util --import "$PKCS8_KEY_PATH" --token "$HSM_TOKEN_LABEL" --label "$HSM_KEY_LABEL" --id 01 --pin "$HSM_USER_PIN"
    touch "$KEY_MARKER"
  fi
fi

exec "$@"
