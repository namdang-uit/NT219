# Citizen Signature Portal - PoC

## Run
```bash
docker compose up --build
```

- Portal: http://localhost:8501
- Backend: http://localhost:8000/health
- TSP: http://localhost:8001/health
- TSP API docs: http://localhost:8001/docs
- Verifier: http://localhost:8002/health

Logs are written to ./logs (backend, tsp, verifier).

## Verify signed PDF (PoC)

TSP exposes `POST /verify-pdf`.

Verifier exposes `POST /verify-pdf`.

- `valid`: cryptographic signature integrity (hash + signature OK)
- `trusted`: certificate chain trusted (self-signed certs will typically show `false` unless you set up a trust chain)
