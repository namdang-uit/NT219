# Citizen Signature Portal - PoC

## Run
```bash
docker compose up --build
```

- Portal: http://localhost:8501
- TSP: http://localhost:8001/health
- TSP API docs: http://localhost:8001/docs

## Verify signed PDF (PoC)

TSP exposes `POST /verify-pdf`.

- `valid`: cryptographic signature integrity (hash + signature OK)
- `trusted`: certificate chain trusted (self-signed certs will typically show `false` unless you set up a trust chain)