# Secure Document Provenance Platform - Production Deployment Guide

**Version**: 1.0 (Phase 15 Hardened)  
**Target Environments**: Docker Compose, Kubernetes, On-Premises Linux (RHEL 9 / Ubuntu 24.04 LTS).

---

## 1. Prerequisites & Host Hardening

* **Operating System**: Linux (Ubuntu 22.04/24.04 LTS, RHEL 8/9, or Debian 12).
* **Container Runtime**: Docker Engine 24+ and Docker Compose v2.20+.
* **Python Runtime** (if running natively): Python 3.14+ with CFFI and OpenSSL 3.0+.
* **Reverse Proxy**: Nginx 1.24+ or Cloudflare / Traefik with TLS 1.3 termination.

---

## 2. Cryptographic Key Generation

In production mode (`ENVIRONMENT=production`), the application strictly **fails closed** if keys are missing or using default development seeds.

Generate cryptographically secure 256-bit CSPRNG keys prior to deployment:

```bash
# 1. Document Key Encryption Key (AES-256)
export DOCUMENT_KEK_BASE64=$(openssl rand -base64 32)

# 2. Recipient Private Key KEK (AES-256)
export RECIPIENT_KEY_KEK_BASE64=$(openssl rand -base64 32)

# 3. Provenance ML-DSA Private Key KEK (AES-256)
export PROVENANCE_KEY_KEK_BASE64=$(openssl rand -base64 32)

# 4. MFA TOTP Secret Protection KEK (AES-256)
export MFA_ENCRYPTION_KEY_BASE64=$(openssl rand -base64 32)

# 5. Forensic Watermarking Master Key (256-bit CSPRNG seed)
export FORENSIC_MASTER_KEY_BASE64=$(openssl rand -base64 32)

# 6. Session Signing Secret (64+ random hex characters)
export SECRET_KEY=$(openssl rand -hex 32)
```

Save these securely in your production secrets store (HashiCorp Vault, AWS Secrets Manager, or systemd credentials). **Never commit real keys to source control.**

---

## 3. Environment Configuration (`.env`)

Create `/opt/sdpp/.env` with strict permissions (`chmod 600 .env`):

```ini
ENVIRONMENT=production
PROJECT_NAME="Secure Document Provenance Platform"
LOG_LEVEL=INFO

# Application Security
SECRET_KEY=<GENERATED_64_CHAR_HEX_SECRET>
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Cryptographic Master Keys (Base64-encoded 32-byte CSPRNG keys)
DOCUMENT_KEK_BASE64=<GENERATED_DOCUMENT_KEK>
RECIPIENT_KEY_KEK_BASE64=<GENERATED_RECIPIENT_KEK>
PROVENANCE_KEY_KEK_BASE64=<GENERATED_PROVENANCE_KEK>
MFA_ENCRYPTION_KEY_BASE64=<GENERATED_MFA_KEK>
FORENSIC_MASTER_KEY_BASE64=<GENERATED_FORENSIC_MASTER_KEY>

# Database Connectivity (Isolated non-root application user)
DATABASE_URL=postgresql://sdpp_app:SuperSecureDbPass123!@db:5432/sdpp_prod

# Persistence & Storage
STORAGE_PATH=/app/storage/encrypted
LEDGER_STORAGE_PATH=/app/storage/ledger

# Network & CORS
CORS_ORIGINS=["https://sdpp.agency.gov"]
```

---

## 4. Docker Deployment Architecture

The platform runs with unprivileged user separation (`appuser`, UID 1000) inside containerized services:

```yaml
# docker-compose.yml excerpt
services:
  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_DB: sdpp_prod
      POSTGRES_USER: sdpp_app
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - internal_net

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    restart: always
    env_file: .env
    volumes:
      - doc_storage:/app/storage/encrypted
      - ledger_storage:/app/storage/ledger
    depends_on:
      - db
    networks:
      - internal_net
      - ingress_net

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    restart: always
    networks:
      - ingress_net
```

Execute initialization:
```bash
docker compose up -d
docker compose exec backend alembic upgrade head
docker compose exec backend python -m app.cli.init_admin
```

---

## 5. Reverse Proxy & TLS Configuration (Nginx)

All external client traffic MUST terminate at a secure TLS 1.3 reverse proxy.

```nginx
server {
    listen 443 ssl http2;
    server_name sdpp.agency.gov;

    ssl_certificate /etc/letsencrypt/live/sdpp.agency.gov/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sdpp.agency.gov/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;

    # Max upload limit (e.g. 50 MB)
    client_max_body_size 50M;

    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
    }
}
```

---

## 6. Health & Readiness Monitoring

The platform provides dual health probes for orchestrator health checking:

* **Liveness Probe**: `GET /health`  
  Returns HTTP 200 `{"status": "ok"}` if the process is responsive.
* **Readiness Probe**: `GET /ready` (or `GET /api/v1/health/ready`)  
  Validates:
  1. PostgreSQL database ping (`SELECT 1`).
  2. Encrypted document storage read/write capability.
  3. Cryptographic KEK operational readiness.
  4. Tamper-evident ledger adapter responsiveness.  
  Returns HTTP 200 with component statuses or HTTP 503 if any subsystem is degraded.

---

## 7. Backup and Disaster Recovery Procedure

### 7.1 Critical Triple Dependency
A backup of the database alone is **insufficient** to recover encrypted documents. Restoration requires the simultaneous synchronization of:

$$\text{Recoverable System} = \text{PostgreSQL Database} + \text{Encrypted Storage} + \text{Cryptographic KEKs}$$

> [!CAUTION]
> If `DOCUMENT_KEK_BASE64` or `RECIPIENT_KEY_KEK_BASE64` is lost, all encrypted documents and recipient private keys become mathematically unrecoverable. Never store KEKs in the same volume as the database backup.

### 7.2 Backup Execution Routine
```bash
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 1. Database dump
pg_dump -U sdpp_app -h localhost -d sdpp_prod -Fc -f /backups/db_${BACKUP_TIMESTAMP}.dump

# 2. Encrypted Document Storage snapshot
tar -czf /backups/storage_${BACKUP_TIMESTAMP}.tar.gz /app/storage/encrypted

# 3. Ledger Volume snapshot
tar -czf /backups/ledger_${BACKUP_TIMESTAMP}.tar.gz /app/storage/ledger
```

### 7.3 Recovery Execution Routine
```bash
# 1. Restore Database
dropdb -U postgres sdpp_prod && createdb -U postgres sdpp_prod
pg_restore -U sdpp_app -d sdpp_prod /backups/db_YYYYMMDD_HHMMSS.dump

# 2. Restore Encrypted Storage
tar -xzf /backups/storage_YYYYMMDD_HHMMSS.tar.gz -C /

# 3. Ensure identical Master KEKs are loaded in .env
# 4. Verify system readiness:
curl -f https://sdpp.agency.gov/api/v1/health/ready
```
