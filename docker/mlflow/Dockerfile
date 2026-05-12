FROM python:3.12-slim

# setuptools <82 required: setuptools 82+ removed pkg_resources, which mlflow 2.13.0 needs
RUN pip install --no-cache-dir \
    "setuptools<82" \
    mlflow==2.13.0 \
    psycopg2-binary==2.9.9 \
    boto3==1.34.0

EXPOSE 5000

# Entrypoint is defined in docker-compose command
