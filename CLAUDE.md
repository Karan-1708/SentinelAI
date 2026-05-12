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
| `docker/` | docker-compose.yml (full stack), docker-compose.dev.yml (dev overrides) |
| `data/` | Dataset download scripts only — raw data is gitignored |
| `notebooks/` | EDA, feature selection, model experiments, SHAP analysis |
| `requirements/` | Pinned Python deps split by concern (base/ml/api/dev) |
| `scripts/` | CLI entry points for training and DB seeding |
| `tests/integration/` | End-to-end tests requiring the full Docker stack |

## Running Locally

```powershell
# Start full stack (requires ~6GB RAM)
docker compose -f docker/docker-compose.yml up -d

# Start dev stack (hot reload, smaller heap, debug ports exposed)
docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml up -d

# Install Python deps
.venv\Scripts\activate
pip install -r requirements/all.txt -r requirements/dev.txt

# Download CICIDS-2017 dataset (one-time, ~8GB)
python data/download_cicids.py

# Run model training
python scripts/run_training.py

# Run unit tests (no Docker required)
pytest ingestion/ models/ api/ -v

# Run integration tests (requires Docker stack running)
pytest tests/integration/ -v
```

## Critical Files

- `docker/docker-compose.yml` — entire service graph; ELK TLS cert bootstrap must succeed first
- `ingestion/normalizer.py` — CICIDS-2017 has leading-space headers and Infinity values; this file fixes them
- `api/main.py` — FastAPI lifespan loads ML models once at startup; never load per-request
- `models/trainer.py` — MLflow autolog + preprocessor artifact persistence
- `explainability/report_generator.py` — ReportLab Platypus PDF with embedded SHAP matplotlib figures

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
  certs into the `certs` Docker volume before ES starts.
- **SHAP multi-class shape**: `TreeExplainer.shap_values(X)` returns shape `(n_classes, n_rows,
  n_features)` for multi-class XGBoost. Index `[predicted_class_idx]` for the right class.
- **MLflow preprocessor**: `mlflow.xgboost.autolog()` logs the XGBoost model but NOT the sklearn
  preprocessor. Log it manually: `mlflow.log_artifact("models/preprocessor.joblib")`.

## Stack Versions

- Python 3.12 (Docker), 3.14.5 (local venv)
- ELK 8.17.0
- XGBoost 2.0.3
- FastAPI 0.111.0
- React 18, Vite 5, TypeScript 5
- PostgreSQL 16
- MLflow 2.13.0

## Services (Docker)

| Service | Internal URL | Dev exposed port |
|---------|-------------|-----------------|
| Elasticsearch | http://elasticsearch:9200 | 9200 |
| Kibana | http://kibana:5601 | 5601 |
| Logstash | logstash:5044 (beats), :5000 (tcp) | — |
| PostgreSQL | postgresql://postgres:5432 | 5432 |
| MLflow | http://mlflow:5000 | 5000 |
| MinIO | http://minio:9000 | 9000, 9001 |
| FastAPI | http://api:8000 | 8000 |
| Nginx | http://nginx:80 | 80 |
