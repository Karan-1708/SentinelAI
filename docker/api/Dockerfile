FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system --gid 1001 appuser && \
    adduser --system --uid 1001 --gid 1001 --no-create-home appuser

COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/all.txt

COPY api/ ./api/
COPY models/ ./models/
COPY explainability/ ./explainability/
COPY ingestion/ ./ingestion/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
