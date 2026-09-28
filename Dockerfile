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

EXPOSE 10000

# Run database migrations, bootstrap admin account, and launch Uvicorn on dynamic $PORT
CMD ["sh", "-c", "python -c \"from alembic.config import Config; from alembic import command; cfg=Config('alembic.ini'); command.upgrade(cfg, 'head')\" || true && (python init_admin.py || true) && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
