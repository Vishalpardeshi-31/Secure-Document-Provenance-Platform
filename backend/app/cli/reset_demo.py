"""Controlled development/demo database reset utility.

SECURITY GUARANTEE:
- STRICTLY REFUSES to run if ENVIRONMENT == 'production'.
- Cleans development test records while preserving migrations and schema structure.
- Prepares fresh demo baseline for Smart India Hackathon evaluation.
"""
import sys
import logging
from sqlalchemy import text
from app.config.settings import settings
from app.database.session import SessionLocal

logger = logging.getLogger("secure_document_platform.cli.reset_demo")


def reset_demo_environment():
    """Resets test data in development/demo mode only."""
    if settings.ENVIRONMENT.lower() == "production":
        print(
            "[SECURITY VIOLATION] Refused: reset_demo cannot and will not execute in production environment.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Resetting demo environment (Current ENVIRONMENT={settings.ENVIRONMENT})...")
    db = SessionLocal()
    try:
        # Ordered cleanup respecting foreign keys
        tables_to_clean = [
            "investigation_audit_records",
            "forensic_detection_results",
            "investigation_evidence",
            "investigation_cases",
            "forensic_fingerprints",
            "viewer_sessions",
            "ledger_outbox",
            "provenance_records",
            "provenance_chain_heads",
            "emergency_access_requests",
            "approvals",
            "approval_requests",
            "decryption_sessions",
            "document_recipients",
            "access_policies",
            "document_versions",
            "documents",
            "recipient_keys",
            "user_mfa_credentials",
            "user_sessions",
            "devices",
            "revoked_tokens",
            "audit_events",
            "users",
        ]

        dialect_name = db.bind.dialect.name if db.bind else "sqlite"
        if dialect_name == "postgresql":
            for table in tables_to_clean:
                db.execute(text(f"TRUNCATE TABLE {table} CASCADE;"))
        else:
            # SQLite
            db.execute(text("PRAGMA foreign_keys = OFF;"))
            for table in tables_to_clean:
                try:
                    db.execute(text(f"DELETE FROM {table};"))
                except Exception:
                    pass
            db.execute(text("PRAGMA foreign_keys = ON;"))

        db.commit()
        print("[SUCCESS] Development demo environment successfully reset to baseline.")
    except Exception as exc:
        db.rollback()
        print(f"[ERROR] Failed to reset demo environment: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    reset_demo_environment()
