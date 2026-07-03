# SentinelAI — Codebase Guide

## Project Overview

Autonomous Threat Intelligence & Incident Response Platform. Acts as a Tier-1 SOC analyst:
ingests logs → detects anomalies → classifies threats → maps to MITRE ATT&CK → generates
explainable incident reports with remediation playbooks.

**Target audience**: Portfolio project for SOC/security engineering roles (Splunk, CrowdStrike,
Microsoft Sentinel). ISO27001 context emphasizes why SHAP explainability matters in regulated
industries.

## Architecture

```
Browser (https) ─┐
                 │
Logs → ELK (Logstash → Elasticsearch) ┐
                                      ├─ nginx (TLS + CSP)
                                      │      │
                                      │      ├─ https  → FastAPI (/api, JWT)
                                      │      │              → IsolationForest + XGBoost
                                      │      │              → MITRE ATT&CK mapping
                                      │      │              → SHAP explanation
                                      │      │              → PostgreSQL (Incident)
                                      │      └─ wss    → WebSocket feed (JWT-authed)
                                      └─ static → React 18 dashboard (zod-validated)
```

Two-stage ML inference:
1. **IsolationForest** (trained on BENIGN-only): flags anomalies, catches zero-days
2. **XGBoost** (supervised multi-class): labels known attack types (DDoS, PortScan, etc.)

If IsolationForest returns "normal", skip XGBoost (early exit for performance). Every model
artifact is SHA-256-verified against `MODEL_MANIFEST_PATH` before `joblib.load` runs — model
files are treated as untrusted input.

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `ingestion/` | CICIDS-2017 normalization, ES bulk indexer, synthetic log generator |
| `models/` | sklearn preprocessor, IsolationForest, XGBoost, MITRE mapper, MLflow trainer |
| `explainability/` | SHAP TreeExplainer, ReportLab PDF report generator |
| `api/` | FastAPI async backend — ingest / predict / incidents / reports / WebSocket |
| `api/auth/` | JWT + argon2id auth module and FastAPI dependencies |
| `dashboard/` | React 18 + Vite + Tailwind — real-time SOC dashboard |
| `dashboard/src/schemas/` | zod runtime validation of every server payload |
| `docker/` | Service-specific configs (logstash pipelines, kibana.yml, nginx.conf, TLS) |
| `data/` | Dataset download scripts + SHA-256 manifest; raw data is gitignored |
| `notebooks/` | EDA, feature selection, model experiments, SHAP analysis |
| `requirements/` | Pinned Python deps split by concern (base/ml/api/dev) |
| `scripts/` | CLI entry points for training, DB seeding, dev cert generation |
| `tests/integration/` | End-to-end tests requiring the full Docker stack |
| `.github/workflows/` | GitHub Actions CI (ruff, bandit, pip-audit, pytest, vitest, build) |

---

## Running Locally

### Prerequisites

- **Docker Desktop** ≥ 4.x (Windows / macOS / Linux), 8 GB RAM recommended
- **Git**
- **openssl** on PATH (for generating dev TLS certs and secrets)

No local Python install required — everything runs inside Docker.

---

### Step 1 — Clone and configure environment

```powershell
git clone https://github.com/Karan-1708/SentinelAI.git
cd SentinelAI

# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

Open `.env` and generate a fresh secret for every `REPLACE_ME_*` placeholder:

```powershell
# 32 bytes of high-entropy random — run once per secret
openssl rand -hex 32
```

The API refuses to boot in `staging` or `production` if any required secret is missing or
still holds a placeholder value (`api/config.py` — `model_validator` enforces this).

---

### Step 1.5 — Bootstrap dev TLS + basic-auth for internal panels

```bash
bash scripts/gen_dev_certs.sh
```

Idempotent. Writes:

- `docker/nginx/certs/server.crt` + `server.key` — self-signed cert for `sentinelai.local` /
  `localhost`. Nginx serves the dashboard and `/api` over HTTPS on port 443.
- `docker/nginx/htpasswd` — dev credentials (`admin` / `dev`) protecting `/mlflow` and
  `/kibana`. Replace before any deployment.

Both paths are gitignored.

---

### Step 2 — Start the full dev stack

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

This starts 9 services. **Elasticsearch takes 60–90 s** to pass its health check.
Wait until it's healthy before proceeding:

```powershell
docker inspect --format="{{.State.Health.Status}}" sentinelai-elasticsearch-1
# Keep running until output is: healthy
```

---

### Step 3 — One-time: set kibana_system password

Required on first launch so Kibana can authenticate with Elasticsearch. Skip on subsequent
starts — the `esdata` volume persists it.

```powershell
docker compose exec elasticsearch bash -c '
  curl -s -X POST -u "elastic:${ELASTIC_PASSWORD}" \
    -H "Content-Type: application/json" \
    https://localhost:9200/_security/user/kibana_system/_password \
    --cacert /usr/share/elasticsearch/config/certs/ca/ca.crt \
    -d "{\"password\":\"${KIBANA_PASSWORD}\"}"
'
```

Expected response: `{}`

---

### Step 4 — Seed the initial admin user

There is no open self-registration — user provisioning is admin-gated. Create the first admin
directly against the database:

```powershell
docker exec -it sentinelai-api-1 `
  python scripts/seed_postgres.py --admin analyst@example.com
```

`seed_postgres.py` reads the password from stdin (never echoed, never logged, never a
command-line argument). It verifies the DB connection, creates tables idempotently, then
inserts the admin. Re-running is safe — existing emails are left unchanged.

---

### Step 5 — Train the models

Training runs inside the API container (Python 3.12, sklearn 1.5.2, XGBoost 2.0.3).

**Option A — Synthetic sample (fast, ~30 s, good for testing)**
```powershell
# Windows
docker cp data\sample\cicids_sample.csv sentinelai-api-1:/tmp/cicids_sample.csv

# macOS / Linux
docker cp data/sample/cicids_sample.csv sentinelai-api-1:/tmp/cicids_sample.csv

docker exec -u root sentinelai-api-1 python -m models.trainer `
  --data-dir /tmp --model-dir /models --max-rows 1000 `
  --mlflow-uri http://mlflow:5000
```

**Option B — Real CICIDS-2017 dataset (~8 GB download, best accuracy)**
```powershell
# First run: bootstrap the SHA-256 manifest (trusted network required).
docker exec sentinelai-api-1 python data/download_cicids.py --skip-hash-check
# Then commit the resulting data/cicids_sha256.txt so every future download is verified.
docker exec -u root sentinelai-api-1 python -m models.trainer `
  --data-dir data/cicids --model-dir /models `
  --mlflow-uri http://mlflow:5000
```

The trainer writes a companion `manifest.json` next to every model artifact (SHA-256, sklearn /
xgboost versions, class list, trained_at). Point `MODEL_MANIFEST_PATH` in `.env` at it so the
API verifies each artifact at startup.

After training completes, fix model file ownership and restart the API:

```powershell
docker exec -u root sentinelai-api-1 chown -R appuser:appuser /models
docker compose -f docker-compose.yml -f docker-compose.dev.yml restart api
```

---

### Step 6 — Verify everything is working

Every mutating endpoint requires a bearer token. The nginx-fronted flow:

```powershell
# 1. Log in and capture the JWT
$login = curl -s -k -X POST https://localhost/api/auth/login `
  -H "Content-Type: application/x-www-form-urlencoded" `
  --data "username=analyst@example.com&password=<your-password>"
$token = ($login | ConvertFrom-Json).access_token

# 2. Health check (unauthenticated by design)
curl -k https://localhost/api/health
# Expected: {"status":"ok","database":"ok","prediction_service":"ready"}

# 3. Test a prediction (authenticated)
curl -k -X POST https://localhost/api/predict `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  --data-binary "@scripts/test_payload.json"
# Expected: threat_label "DDoS", mitre_techniques [T1498, T1499], top_shap_features [...]
```

Open **https://localhost/** — the React dashboard loads a login screen. Sign in with the admin
credentials created in Step 4 and the live incident feed streams over `wss://`.

> The self-signed cert triggers a browser warning on first visit. Accept it once for dev.

---

### Service URLs (dev mode)

| Service | URL | Credentials |
|---------|-----|-------------|
| React dashboard | https://localhost/ | admin created in Step 4 |
| FastAPI (via nginx) | https://localhost/api/ | JWT from `/api/auth/login` |
| FastAPI (direct dev) | http://localhost:8000 | JWT (no TLS — dev only) |
| Vite dev server | http://localhost:3000 | — (proxies `/api` and `/ws`) |
| MLflow UI | https://localhost/mlflow/ | `admin` / `dev` (htpasswd) |
| Kibana | https://localhost/kibana/ | `admin` / `dev` (htpasswd) |
| MinIO console | http://localhost:9001 | `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` from .env |
| Elasticsearch | https://localhost:9200 | `elastic` / `ELASTIC_PASSWORD` from .env |
| PostgreSQL | localhost:5432 | `sentinel` / `POSTGRES_PASSWORD` from .env |

> **Note:** In dev mode a separate Vite server runs on port 3000 and MLflow's direct port is 5001
> (host port 5000 is used by Logstash syslog input). Production traffic should always flow
> through the nginx reverse proxy on 443.

---

### Stopping the stack

```powershell
# Stop all containers (volumes preserved)
docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# Full reset — also deletes all data volumes
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
```

---

## Authentication model

- **Roles**: `viewer` < `analyst` < `admin` (hierarchy in `api/auth/dependencies.py`).
- **Tokens**: HS256 JWT, 30-minute default TTL, signed with `API_SECRET_KEY`. Claims include
  `sub` (user UUID), `role`, `iss`, `aud`, `iat`, `exp`.
- **Password hashing**: Argon2id via `argon2-cffi`. `/auth/login` verifies against a dummy hash
  on unknown emails to eliminate the timing side-channel that would otherwise reveal which
  emails exist.
- **Rate limits**: SlowAPI global limiter (120/min default). `/auth/login` capped at 5/min per
  IP; `/predict` and `/ingest` at 60/min; `/reports/{id}` at 30/min.
- **WebSocket**: `wss://<host>/ws/feed?token=<jwt>` — token is required; server also validates
  `Origin` against `CORS_ORIGINS` (CSWSH defense). Bad token → close code 4401; bad origin →
  4403; server at capacity → 4408.
- **Dashboard token storage**: in-memory (Zustand). Not `localStorage` — an XSS on the app would
  otherwise exfiltrate a long-lived token. Trade-off is a login round-trip on tab refresh.

---

## Security posture

The controls now in place, at a glance:

- **Transport**: nginx terminates TLS 1.2 / 1.3; HTTP → HTTPS redirect; HSTS `max-age=63072000`.
- **Headers**: strict CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` denies camera / mic /
  geolocation.
- **Auth**: JWT bearer on every HTTP + WS route; role hierarchy; admin-only registration.
- **CORS**: explicit origin allow-list; explicit method + header allow-list (no `*`).
- **Rate limits**: SlowAPI, per-route.
- **Input validation**: Pydantic v2 field validators cap features dict size (256 entries), IP
  addresses parsed via `IPvAnyAddress`, values must be finite and bounded (`|x| ≤ 1e12`).
- **Model integrity**: SHA-256 manifest verification before every `joblib.load` /
  `xgb.Booster.load_model`. Production refuses to load without a manifest.
- **PDF safety**: every user-influenced string is escaped via `xml.sax.saxutils.escape`; IPs are
  validated via `ipaddress`; MITRE URLs are scheme-checked. Blanket `except` swallows removed —
  render failures surface as `ReportRenderError`.
- **Dashboard**: zod schemas validate every REST + WS payload; `safeHttpUrl` rejects
  `javascript:` / `data:` schemes before rendering as `href`; `ErrorBoundary` around all routes.
- **Container**: API runs `read_only: true`, `cap_drop: ALL`, `no-new-privileges`.
- **Errors**: global exception handlers emit only a generic `detail` + request-ID; tracebacks
  stay in server logs.
- **Dataset**: CICIDS downloader streams to a `.partial` sidecar, SHA-256-verifies against
  `data/cicids_sha256.txt`, retries with exponential backoff, normalises filenames to defeat
  zip-slip.

Full disclosure policy: [SECURITY.md](SECURITY.md).

---

## Testing

```powershell
# Python — 44 tests across API, models, ingestion
pytest api/tests models/tests ingestion/tests -q

# Dashboard — vitest suites for zod schemas + URL guard
npm --prefix dashboard run test
```

CI (`.github/workflows/ci.yml`) runs on every push and pull request:

- `ruff check`, `mypy` (advisory), `bandit -r`, `pip-audit --strict` on requirements
- `pytest -q --cov` on the Python surface
- `npm run test` + `npm run build` on the dashboard

`conftest.py` at the repo root sets `random.seed(0)` and `np.random.seed(0)` autouse so every
test is deterministic regardless of run order.

---

## Critical Files

- `docker-compose.yml` — entire service graph; ELK TLS cert bootstrap must succeed first
- `docker/nginx/nginx.conf` — TLS termination, CSP, HSTS, security headers; single external ingress
- `api/main.py` — FastAPI lifespan loads ML models once; global exception handlers; SlowAPI middleware
- `api/auth/security.py` — JWT create / decode + argon2id password helpers
- `api/services/prediction_service.py` — SHA-256 manifest verification before deserialisation
- `ingestion/normalizer.py` — CICIDS-2017 leading-space headers, Infinity values, fine vs coarse label maps
- `models/threat_classifier.py` — unseen-label filter, deterministic encoder path, manifest sidecar
- `explainability/report_generator.py` — Platypus PDF with `xml.sax.saxutils.escape` on every user field
- `dashboard/src/schemas/incident.ts` — zod schemas + `safeHttpUrl` guard

---

## Known Gotchas

- **CICIDS-2017 headers**: All column names have leading spaces (` Label`, ` Flow Duration`).
  `normalizer.py` strips them with `df.columns.str.strip()`.
- **CICIDS-2017 Infinity values**: `Flow Bytes/s` and `Flow Packets/s` contain `Infinity`.
  Replace with `np.nan` then impute with column median.
- **numpy pin**: SHAP 0.45.x requires `numpy<2.0`. Pin to `numpy==1.26.4`.
- **XGBoost class_weight**: XGBoost doesn't accept `class_weight='balanced'`. Use
  `compute_class_weight('balanced', ...)` and pass the result as `sample_weight` to `.fit()`.
- **IsolationForest training data**: Train ONLY on BENIGN rows. Training on all classes corrupts
  the normal-distribution baseline.
- **ELK 8.x TLS**: ELK 8 has security enabled by default. The `setup` service bootstraps TLS
  certs into the `certs` Docker volume before ES starts. Cert directory permissions must be
  `755` (not `750`) so Logstash can read them.
- **SHAP multi-class shape**: `TreeExplainer.shap_values(X)` returns different shapes across
  SHAP releases. `shap_explainer.py` asks the model itself for the winning class instead of
  guessing from SHAP sums.
- **MLflow preprocessor**: `mlflow.xgboost.autolog()` logs the XGBoost model but NOT the sklearn
  preprocessor. Log it manually: `mlflow.log_artifact("models/preprocessor.joblib")`.
- **sklearn version lock**: sklearn 1.6+ added `__sklearn_tags__` protocol that XGBoost 2.0.x
  doesn't implement. Pin to `scikit-learn==1.5.2`.
- **setuptools pin**: setuptools 82+ removed `pkg_resources` which MLflow 2.13.0 needs.
  Pin to `setuptools<82`.
- **Model ownership**: Models are written by root (training) but the API runs as `appuser`.
  After training, run `chown -R appuser:appuser /models` inside the container.
- **openssl required**: `scripts/gen_dev_certs.sh` needs `openssl` on PATH.
- **Model manifest required in prod**: `MODEL_MANIFEST_PATH` unset while `APP_ENV=production`
  is fatal — the API will not deserialize an unverified model file.
- **CICIDS downloader is strict by default**: the first-ever download needs
  `--skip-hash-check`, after which `data/cicids_sha256.txt` should be populated and committed
  so every subsequent run verifies.

---

## Stack Versions

**Runtime**
- Python 3.12 (Docker)
- Node 24 (Docker)
- ELK 8.17.0
- XGBoost 2.0.3 + scikit-learn 1.5.2
- FastAPI 0.111.0
- React 18, Vite 5, TypeScript 5
- PostgreSQL 16
- MLflow 2.13.0
- MinIO (latest)

**Security stack**
- pyjwt 2.9.0 (HS256 signing)
- argon2-cffi 23.1.0 (password hashing)
- slowapi 0.1.9 (rate limiting)
- zod 3.23.8 (dashboard runtime validation)
- aiosqlite 0.20.0 (dev tests only)
