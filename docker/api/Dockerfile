FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (cached layer)
COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/all.txt

# Copy source code
COPY api/ ./api/
COPY models/ ./models/
COPY explainability/ ./explainability/
COPY ingestion/ ./ingestion/

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
