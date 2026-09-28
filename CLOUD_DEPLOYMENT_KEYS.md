# Cloud Deployment Configuration & Generated Secret Keys

Use these generated keys and configurations when deploying your application to **Render**, **Neon**, and **Vercel**.

---

## 1. Cryptographically Secure Production Keys

Copy and paste these exact values into your **Render** Web Service Environment Variables:

| Environment Variable | Value | Description |
|---|---|---|
| `ENVIRONMENT` | `production` | Enables production security enforcement |
| `LOG_LEVEL` | `INFO` | Standard production logging |
| `SECRET_KEY` | `537b56ebee66b8d860ed9239948d2331e0e6932f9834c58507ff97f1a48d8603` | 256-bit token signing secret |
| `DOCUMENT_KEK_BASE64` | `81jkRzIpBtb0HqMv8C6EjVBX24t+aUbOxYujKelpvME=` | AES-256 Key Encryption Key for documents |
| `RECIPIENT_KEY_KEK_BASE64` | `Zwth/kn5mIIH1QrG6B18KboDQDYALXhRx/jUltmIQGI=` | AES-256 Key for recipient private keys |
| `PROVENANCE_KEY_KEK_BASE64` | `YmXtyGbi0vODo/sVxZbPoJv0bfcs+k7OjG9g4gbVjbc=` | Key for ML-DSA provenance signing keys |
| `MFA_ENCRYPTION_KEY_BASE64` | `ZPUxPfngj5bIgypZYOcAqmTfEmZE0d98WvScVY+l1Cg=` | Key for user MFA TOTP secrets |
| `FORENSIC_MASTER_KEY_BASE64` | `6yxstDvfxhntvgzQv1pqT+W3xNxDgcMwzx0T0oTl1ZA=` | Key for forensic fingerprint derivation |
| `INITIAL_ADMIN_USERNAME` | `admin` | Default initial admin account username |
| `INITIAL_ADMIN_EMAIL` | `admin@security.internal` | Default initial admin account email |
| `INITIAL_ADMIN_PASSWORD` | `Strict#Passphrase2026!` | Initial password (change upon first login) |
| `DATABASE_URL` | *(Paste connection string from Neon.tech)* | PostgreSQL database connection URL |
| `CORS_ORIGINS` | `http://localhost:5173,https://your-frontend.vercel.app` | Allowed origins (update with your Vercel URL) |

---

## 2. Deployment Instructions (Step-by-Step)

### Step 1: Free PostgreSQL on Neon.tech (1 minute)
1. Go to [https://neon.tech](https://neon.tech) and sign up with GitHub.
2. Click **Create Project**, name it `secure-docs`, and select PostgreSQL 16.
3. In the dashboard, copy the **Connection string** (Direct or Pooled).
   - Example: `postgresql://sdpp_owner:Abc123xyz@ep-cool-fog-123456.us-east-2.aws.neon.tech/neondb?sslmode=require`

### Step 2: Backend on Render.com (2 minutes)
1. Go to [https://render.com](https://render.com) and log in with GitHub.
2. Click **New +** > **Web Service** (or **Blueprint**).
3. Connect your repository: `Vishalpardeshi-31/Secure-Document-Provenance-Platform`.
4. Render will detect the `Dockerfile` inside `./backend`.
   - **Root Directory**: `backend` (or leave default if using root Docker context)
   - **Environment**: Docker
   - **Plan**: Free
5. In the **Environment Variables** section, paste all the keys listed in Section 1 above.
6. Click **Deploy Web Service**.
7. Once deployed, Render will provide your public backend URL (e.g., `https://sdpp-backend.onrender.com`).

### Step 3: Frontend on Vercel.com (1 minute)
1. Go to [https://vercel.com](https://vercel.com) and log in with GitHub.
2. Click **Add New...** > **Project** and select `Secure-Document-Provenance-Platform`.
3. In **Root Directory**, click **Edit** and select `frontend`.
4. Expand **Environment Variables**:
   - Add: `VITE_API_URL` = `https://your-backend.onrender.com` (your backend URL from Step 2)
5. Click **Deploy**.

---

## 3. Post-Deployment Verification
- Backend Health Check: `https://your-backend.onrender.com/api/v1/health`
- Frontend: Open your Vercel URL, log in with `admin` and `Strict#Passphrase2026!`.
