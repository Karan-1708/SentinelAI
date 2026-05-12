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
Logs → ELK (Logstash → Elasticsearch) → FastAPI (/predict) → IsolationForest + XGBoost
     → MITRE ATT&CK mapping → SHAP explanation → PostgreSQL (Incident) → WebSocket → React
```

Two-stage ML inference:
1. **IsolationForest** (trained on BENIGN-only): flags anomalies, catches zero-days
2. **XGBoost** (supervised multi-class): labels known attack types (DDoS, PortScan, etc.)

If IsolationForest returns "normal", skip XGBoost (early exit for performance).

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `ingestion/` | CICIDS-2017 normalization, ES bulk indexer, synthetic log generator |
| `models/` | sklearn preprocessor, IsolationForest, XGBoost, MITRE mapper, MLflow trainer |
| `explainability/` | SHAP TreeExplainer, ReportLab PDF report generator |
| `api/` | FastAPI async backend — ingest/predict/incidents/reports/WebSocket endpoints |
| `dashboard/` | React 18 + Vite + Tailwind — real-time SOC dashboard |
| `docker/` | Service-specific configs (logstash pipelines, kibana.yml, nginx.conf, etc.) |
| `data/` | Dataset download scripts only — raw data is gitignored |
| `notebooks/` | EDA, feature selection, model experiments, SHAP analysis |
| `requirements/` | Pinned Python deps split by concern (base/ml/api/dev) |
| `scripts/` | CLI entry points for training and DB seeding |
| `tests/integration/` | End-to-end tests requiring the full Docker stack |

---

## Running Locally

### Prerequisites

- **Docker Desktop** ≥ 4.x (Windows / macOS / Linux), 8 GB RAM recommended
- **Git**

No local Python install required — everything runs inside Docker.

---

### Step 1 — Clone and configure environment

```powershell
git clone <repo-url>
cd SentinelAI

# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

Open `.env` and replace all `changeme_*` values with your own secrets.

**Critical format note** — `CORS_ORIGINS` must be a JSON array (pydantic-settings v2):
```
CORS_ORIGINS=["http://localhost:3000","http://localhost:8000"]
```

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

This is required on first launch so Kibana can authenticate with Elasticsearch.
Skip on subsequent starts — the `esdata` volume persists it.

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

### Step 4 — Train the models

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
docker exec sentinelai-api-1 python data/download_cicids.py
docker exec -u root sentinelai-api-1 python -m models.trainer `
  --data-dir data/cicids --model-dir /models `
  --mlflow-uri http://mlflow:5000
```

After training completes, fix model file ownership and restart the API:

```powershell
docker exec -u root sentinelai-api-1 chown -R appuser:appuser /models
docker compose -f docker-compose.yml -f docker-compose.dev.yml restart api
```

---

### Step 5 — Verify everything is working

```powershell
# API health check
curl http://localhost:8000/health
# Expected: {"status":"ok","database":"ok","prediction_service":"ready"}

# Test a prediction
curl -X POST http://localhost:8000/predict `
  -H "Content-Type: application/json" `
  --data-binary "@scripts/test_payload.json"
# Expected: threat_label "DDoS", mitre_techniques [T1498, T1499], top_shap_features [...]
```

Open **http://localhost:3000** — the React dashboard should load with a live incident feed.

---

### Service URLs (dev mode)

| Service | URL | Credentials |
|---------|-----|-------------|
| React dashboard | http://localhost:3000 | — |
| FastAPI | http://localhost:8000 | — |
| MLflow UI | http://localhost:5001 | — |
| Kibana | http://localhost:5601 | `elastic` / `ELASTIC_PASSWORD` from .env |
| MinIO console | http://localhost:9001 | `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` from .env |
| Elasticsearch | https://localhost:9200 | `elastic` / `ELASTIC_PASSWORD` from .env |
| PostgreSQL | localhost:5432 | `sentinel` / `POSTGRES_PASSWORD` from .env |

> **Note:** MLflow is on port **5001** (not 5000) in dev mode — Logstash syslog input binds host port 5000.

---

### Stopping the stack

```powershell
# Stop all containers (volumes preserved)
docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# Full reset — also deletes all data volumes
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
```

---

## Critical Files

- `docker-compose.yml` — entire service graph; ELK TLS cert bootstrap must succeed first
- `ingestion/normalizer.py` — CICIDS-2017 has leading-space headers and Infinity values; this file fixes them
- `api/main.py` — FastAPI lifespan loads ML models once at startup; never load per-request
- `models/trainer.py` — MLflow autolog + preprocessor artifact persistence
- `explainability/report_generator.py` — ReportLab Platypus PDF with embedded SHAP matplotlib figures

---

## Known Gotchas

- **CICIDS-2017 headers**: All column names have leading spaces (` Label`, ` Flow Duration`).
  `normalizer.py` strips them with `df.columns.str.strip()`.
- **CICIDS-2017 Infinity values**: `Flow Bytes/s` and `Flow Packets/s` contain `Infinity`.
  Replace with `np.nan` then impute with column median.
- **numpy pin**: SHAP 0.45.x requires `numpy<2.0`. Pin to `numpy==1.26.4`.
- **XGBoost class_weight**: XGBoost doesn't accept `class_weight='balanced'`. Use
  `compute_class_weight('balanced', ...)` and pass result as `sample_weight` to `.fit()`.
- **IsolationForest training data**: Train ONLY on BENIGN rows. Training on all classes corrupts
  the normal distribution baseline.
- **ELK 8.x TLS**: ELK 8 has security enabled by default. The `setup` service bootstraps TLS
  certs into the `certs` Docker volume before ES starts. Cert directory permissions must be
  `755` (not `750`) so Logstash can read them.
- **SHAP multi-class shape**: `TreeExplainer.shap_values(X)` returns shape `(n_classes, n_rows,
  n_features)` for multi-class XGBoost. Index `[predicted_class_idx]` for the right class.
- **MLflow preprocessor**: `mlflow.xgboost.autolog()` logs the XGBoost model but NOT the sklearn
  preprocessor. Log it manually: `mlflow.log_artifact("models/preprocessor.joblib")`.
- **sklearn version lock**: sklearn 1.6+ added `__sklearn_tags__` protocol that XGBoost 2.0.x
  doesn't implement. Pin to `scikit-learn==1.5.2`.
- **setuptools pin**: setuptools 82+ removed `pkg_resources` which MLflow 2.13.0 needs.
  Pin to `setuptools<82`.
- **Model ownership**: Models are written by root (training) but the API runs as `appuser`.
  After training, run `chown -R appuser:appuser /models` inside the container.

---

## Stack Versions

- Python 3.12 (Docker)
- ELK 8.17.0
- XGBoost 2.0.3 + scikit-learn 1.5.2
- FastAPI 0.111.0
- React 18, Vite 5, TypeScript 5
- PostgreSQL 16
- MLflow 2.13.0
- MinIO (latest)
