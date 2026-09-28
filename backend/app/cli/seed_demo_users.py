"""Pre-seeds genuine SIH demonstration accounts, devices, and cryptographic keys.

CRITICAL GUARANTEES:
- Strictly refuses execution in production environment (ENVIRONMENT == 'production').
- Generates REAL database users with Argon2id-hashed passwords via UserService.
- Registers REAL hardware device records via DeviceService.
- Provisions REAL NIST FIPS 203 ML-KEM-768 recipient key pairs via RecipientKeyManager.
- No mocks, no simulated security, no hardcoded bypasses.
"""
import os
import sys
import logging

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.config.settings import settings
from app.database.session import SessionLocal
from app.models.user import User
from app.models.role import Role, UserRole
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager

logger = logging.getLogger("secure_document_platform.cli.seed_demo_users")

DEMO_ACCOUNTS = [
    {
        "username": "admin",
        "email": "admin@agency.gov",
        "password": "AdminPassword123!",
        "role": UserRole.ADMIN,
        "device_name": "Admin Control Terminal (Dell Precision)",
        "device_fingerprint": "fp-admin-dell-001",
    },
    {
        "username": "officer_sharma",
        "email": "officer_sharma@agency.gov",
        "password": "OfficerPass123!",
        "role": UserRole.OFFICER,
        "device_name": "Ministry Workstation (HP EliteBook)",
        "device_fingerprint": "fp-officer-hp-002",
    },
    {
        "username": "rec_verma",
        "email": "rec_verma@agency.gov",
        "password": "RecVermaPass123!",
        "role": UserRole.RECIPIENT,
        "device_name": "Field Terminal Alpha (ThinkPad T14)",
        "device_fingerprint": "fp-rec-verma-003",
        "provision_mlkem": True,
    },
    {
        "username": "rec_patel",
        "email": "rec_patel@agency.gov",
        "password": "RecPatelPass123!",
        "role": UserRole.RECIPIENT,
        "device_name": "Field Terminal Beta (ThinkPad X1)",
        "device_fingerprint": "fp-rec-patel-004",
        "provision_mlkem": True,
    },
    {
        "username": "auditor_singh",
        "email": "auditor_singh@agency.gov",
        "password": "AuditorPass123!",
        "role": UserRole.AUDITOR,
        "device_name": "Investigation Station (MacBook Pro)",
        "device_fingerprint": "fp-auditor-mac-005",
    },
]


def seed_demo_users():
    """Seeds authentic SIH demonstration accounts, devices, and ML-KEM keys."""
    if settings.ENVIRONMENT.lower() == "production":
        print(
            "[SECURITY VIOLATION] Refused: seed_demo_users cannot and will not execute in production environment.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Seeding SIH demonstration accounts (ENVIRONMENT={settings.ENVIRONMENT})...")
    db = SessionLocal()
    try:
        # 1. Ensure Roles exist
        for role_enum in UserRole:
            role_record = db.query(Role).filter(Role.name == role_enum.value).first()
            if not role_record:
                role_record = Role(
                    name=role_enum.value,
                    description=f"System role for {role_enum.value.lower()} users.",
                )
                db.add(role_record)
        db.commit()

        # 2. Seed Admin first so admin can provision recipient keys
        created_users = {}
        for acc in DEMO_ACCOUNTS:
            existing = db.query(User).filter(User.username == acc["username"]).first()
            if existing:
                print(f"  [+] User '{acc['username']}' already exists (ID: {existing.id})")
                user = existing
            else:
                user = UserService.create_user(
                    db=db,
                    username=acc["username"],
                    email=acc["email"],
                    plain_password=acc["password"],
                    role=acc["role"],
                )
                print(f"  [+] Created user '{acc['username']}' ({acc['role'].value}, ID: {user.id})")
            created_users[acc["username"]] = user

            # Register device
            dev = DeviceService.register_device(
                db=db,
                user_id=user.id,
                device_name=acc["device_name"],
                device_fingerprint=acc["device_fingerprint"],
            )
            print(f"      - Device registered: '{dev.device_name}' (ID: {dev.id}, Status: {dev.status})")

        # 3. Provision ML-KEM-768 recipient keys for Recipient accounts
        admin_user = created_users["admin"]
        for acc in DEMO_ACCOUNTS:
            if acc.get("provision_mlkem"):
                user = created_users[acc["username"]]
                existing_key = RecipientKeyManager.get_active_key(db, user.id)
                if not existing_key:
                    key_rec = RecipientKeyManager.provision_recipient_key(
                        db=db,
                        user=user,
                        actor=admin_user,
                    )
                    print(f"      - ML-KEM-768 key provisioned: Version {key_rec.key_version} (Status: {key_rec.status})")
                else:
                    print(f"      - ML-KEM-768 key already active: Version {existing_key.key_version}")

        print("\n" + "=" * 60)
        print("  SIH 2026 DEMONSTRATION ACCOUNTS READY")
        print("=" * 60)
        for acc in DEMO_ACCOUNTS:
            print(f"  Role: {acc['role'].value:<10} | User: {acc['username']:<16} | Pass: {acc['password']}")
        print("=" * 60 + "\n")

    except Exception as exc:
        db.rollback()
        print(f"[ERROR] Failed to seed demo accounts: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_users()
