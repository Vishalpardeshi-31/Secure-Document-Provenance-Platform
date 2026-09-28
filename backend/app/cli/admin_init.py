import argparse
import getpass
import os
import sys

# Ensure backend directory is always in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.database.session import SessionLocal
from app.models.user import User
from app.models.role import Role, UserRole
from app.services.user_service import UserService


def initialize_admin():
    parser = argparse.ArgumentParser(
        description="Secure initialization utility for the first Administrator account."
    )
    parser.add_argument(
        "--username",
        help="Administrator username (or set INITIAL_ADMIN_USERNAME env var)",
    )
    parser.add_argument(
        "--email",
        help="Administrator email (or set INITIAL_ADMIN_EMAIL env var)",
    )
    parser.add_argument(
        "--password",
        help="Administrator password (or set INITIAL_ADMIN_PASSWORD env var, or prompt interactively)",
    )
    args = parser.parse_args()

    username = args.username or os.getenv("INITIAL_ADMIN_USERNAME")
    email = args.email or os.getenv("INITIAL_ADMIN_EMAIL")
    password = args.password or os.getenv("INITIAL_ADMIN_PASSWORD")

    if not username:
        if not sys.stdin or not sys.stdin.isatty():
            print("[INFO] No INITIAL_ADMIN_USERNAME specified and non-interactive shell. Skipping admin auto-init.", file=sys.stderr)
            return
        username = input("Enter Administrator Username: ").strip()
    if not email:
        if not sys.stdin or not sys.stdin.isatty():
            email = f"{username}@security.internal"
        else:
            email = input("Enter Administrator Email: ").strip()
    if not password:
        if not sys.stdin or not sys.stdin.isatty():
            print("[INFO] No INITIAL_ADMIN_PASSWORD specified and non-interactive shell. Skipping admin auto-init.", file=sys.stderr)
            return
        password = getpass.getpass("Enter Administrator Password (min 12 chars, upper/lower/digit/symbol): ")
        password_confirm = getpass.getpass("Confirm Administrator Password: ")
        if password != password_confirm:
            print("[ERROR] Passwords do not match. Aborting initialization.", file=sys.stderr)
            sys.exit(1)

    db = SessionLocal()
    try:
        # Check if any admin already exists
        existing_admin = db.query(User).filter(User.role == UserRole.ADMIN.value).first()
        if existing_admin:
            print(
                f"[INFO] Administrator account already exists (username: {existing_admin.username}). "
                "No additional default admin can be initialized via this tool.",
                file=sys.stderr,
            )
            sys.exit(0)

        # Ensure roles exist in roles table
        for role_enum in UserRole:
            role_record = db.query(Role).filter(Role.name == role_enum.value).first()
            if not role_record:
                role_record = Role(
                    name=role_enum.value,
                    description=f"System role for {role_enum.value.lower()} users.",
                )
                db.add(role_record)
        db.commit()

        # Find the ADMIN role id
        admin_role_obj = db.query(Role).filter(Role.name == UserRole.ADMIN.value).first()

        # Create user through UserService (which validates password strength and hashes with Argon2id)
        admin_user = UserService.create_user(
            db=db,
            username=username,
            email=email,
            plain_password=password,
            role=UserRole.ADMIN,
        )
        if admin_role_obj:
            admin_user.role_id = admin_role_obj.id
            db.commit()

        print(f"[SUCCESS] First Administrator '{admin_user.username}' successfully created with ID: {admin_user.id}")
    except ValueError as val_err:
        print(f"[SECURITY VALIDATION ERROR] {val_err}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Failed to initialize administrator: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    initialize_admin()
