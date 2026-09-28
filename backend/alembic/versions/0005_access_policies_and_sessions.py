"""enhance access policies and decryption sessions for Phase 5

Revision ID: 0005_access_policies_and_sessions
Revises: 0004_add_recipient_keys
Create Date: 2026-09-27 23:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0005_access_policies_and_sessions'
down_revision: Union[str, None] = '0004_add_recipient_keys'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add Phase 5 columns to access_policies table
    op.add_column('access_policies', sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('access_policies', sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True))
    op.add_column('access_policies', sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True))
    op.add_column('access_policies', sa.Column('max_decryptions', sa.Integer(), nullable=True))
    op.add_column('access_policies', sa.Column('require_registered_device', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('access_policies', sa.Column('require_approval', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('access_policies', sa.Column('created_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True))

    # 2. Add Phase 5 columns to decryption_sessions table
    op.add_column('decryption_sessions', sa.Column('authorized_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('decryption_sessions', sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('decryption_sessions', sa.Column('failure_reason_code', sa.String(length=64), nullable=True))


def downgrade() -> None:
    # Drop columns from decryption_sessions
    op.drop_column('decryption_sessions', 'failure_reason_code')
    op.drop_column('decryption_sessions', 'completed_at')
    op.drop_column('decryption_sessions', 'authorized_at')

    # Drop columns from access_policies
    op.drop_column('access_policies', 'created_by')
    op.drop_column('access_policies', 'require_approval')
    op.drop_column('access_policies', 'require_registered_device')
    op.drop_column('access_policies', 'max_decryptions')
    op.drop_column('access_policies', 'valid_until')
    op.drop_column('access_policies', 'valid_from')
    op.drop_column('access_policies', 'enabled')
