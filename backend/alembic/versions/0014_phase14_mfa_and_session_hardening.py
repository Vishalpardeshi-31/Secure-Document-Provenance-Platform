"""Phase 14: Authentication, Device, Session, and MFA Hardening schema.

Revision ID: 0014_phase14_mfa_and_session_hardening
Revises: 0013_investigation_cases
Create Date: 2026-09-28 10:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0014_phase14_mfa_and_session_hardening'
down_revision: Union[str, None] = '0013_investigation_cases'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. user_mfa_credentials
    op.create_table(
        'user_mfa_credentials',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('method', sa.String(length=32), nullable=False, server_default='TOTP'),
        sa.Column('encrypted_secret', sa.String(length=512), nullable=False),
        sa.Column('secret_nonce', sa.String(length=64), nullable=False),
        sa.Column('encryption_key_version', sa.String(length=32), nullable=False, server_default='v1'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_attempt_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_user_mfa_credentials_user_id', 'user_mfa_credentials', ['user_id'])
    op.create_index('ix_user_mfa_credentials_enabled', 'user_mfa_credentials', ['enabled'])

    # 2. user_sessions
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', sa.String(length=36), sa.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True),
        sa.Column('token_jti', sa.String(length=64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('authentication_level', sa.String(length=32), nullable=False, server_default='NORMAL'),
        sa.Column('mfa_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ip_metadata', sa.String(length=64), nullable=True),
        sa.Column('user_agent_metadata', sa.String(length=255), nullable=True),
    )
    op.create_index('ix_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('ix_user_sessions_device_id', 'user_sessions', ['device_id'])
    op.create_index('ix_user_sessions_token_jti', 'user_sessions', ['token_jti'])

    # 3. Add lockout columns to users
    op.add_column('users', sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))

    # 4. Add public_key and challenge columns to devices
    op.add_column('devices', sa.Column('public_key', sa.String(length=512), nullable=True))
    op.add_column('devices', sa.Column('challenge_nonce', sa.String(length=64), nullable=True))
    op.add_column('devices', sa.Column('challenge_expires_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'challenge_expires_at')
    op.drop_column('devices', 'challenge_nonce')
    op.drop_column('devices', 'public_key')
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'failed_login_attempts')
    op.drop_table('user_sessions')
    op.drop_table('user_mfa_credentials')
