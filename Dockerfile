FROM python:3.12-slim

WORKDIR /app

# Install system dependencies needed for compiling cryptography / postgres dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies from backend folder
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend application source and migrations into /app
COPY backend/ .

# Create non-root application user and ensure permissions on runtime storage
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/storage/encrypted /app/storage/ledger && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Health check against live health endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run database migrations, bootstrap admin account if env provided, and launch Uvicorn on dynamic $PORT
CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && (python init_admin.py || true) && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
