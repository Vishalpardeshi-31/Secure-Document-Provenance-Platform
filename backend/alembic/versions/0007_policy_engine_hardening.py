"""Policy engine hardening: versioning, allowed roles, atomic counters, and device status

Revision ID: 0007_policy_hardening
Revises: 0006_crypto_hardening
Create Date: 2026-09-28 01:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0007_policy_hardening'
down_revision: Union[str, None] = '0006_crypto_hardening'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update access_policies table
    op.add_column('access_policies', sa.Column('policy_version', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('access_policies', sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'))
    op.add_column('access_policies', sa.Column('allowed_roles', sa.String(length=255), nullable=True))
    op.add_column('access_policies', sa.Column('consumed_decryptions', sa.Integer(), nullable=False, server_default='0'))
    op.create_index('ix_access_policies_status', 'access_policies', ['status'])

    # 2. Update devices table
    op.add_column('devices', sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'))
    op.add_column('devices', sa.Column('device_identifier_hash', sa.String(length=64), nullable=True))
    op.add_column('devices', sa.Column('registered_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_devices_status', 'devices', ['status'])
    op.create_index('ix_devices_device_identifier_hash', 'devices', ['device_identifier_hash'])

    # 3. Update decryption_sessions table
    op.add_column('decryption_sessions', sa.Column('policy_version', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('decryption_sessions', 'policy_version')

    op.drop_index('ix_devices_device_identifier_hash', table_name='devices')
    op.drop_index('ix_devices_status', table_name='devices')
    op.drop_column('devices', 'revoked_at')
    op.drop_column('devices', 'registered_at')
    op.drop_column('devices', 'device_identifier_hash')
    op.drop_column('devices', 'status')

    op.drop_index('ix_access_policies_status', table_name='access_policies')
    op.drop_column('access_policies', 'consumed_decryptions')
    op.drop_column('access_policies', 'allowed_roles')
    op.drop_column('access_policies', 'status')
    op.drop_column('access_policies', 'policy_version')
