FROM python:3.12-slim

RUN addgroup --system --gid 1001 mlflow && \
    adduser --system --uid 1001 --gid 1001 --no-create-home mlflow

# setuptools <82 required: setuptools 82+ removed pkg_resources, which mlflow 2.13.0 needs
RUN pip install --no-cache-dir \
    "setuptools<82" \
    mlflow==2.13.0 \
    psycopg2-binary==2.9.9 \
    boto3==1.34.0

WORKDIR /app
RUN chown mlflow:mlflow /app

USER mlflow

EXPOSE 5000

# Entrypoint is defined in docker-compose command
