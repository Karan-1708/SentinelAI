-- SentinelAI PostgreSQL initialization
-- This file runs once on first container start via /docker-entrypoint-initdb.d/
-- Alembic manages all subsequent schema changes

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- MLflow uses the same DB (different schema) — no additional setup needed
-- Alembic will create the sentinelai tables on first API startup
