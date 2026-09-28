"""add revoked_tokens table and department is_active column

Revision ID: 0002_add_revoked_tokens
Revises: 0001_initial_schema
Create Date: 2026-09-27 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002_add_revoked_tokens'
down_revision: Union[str, None] = '0001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add is_active column to departments
    op.add_column(
        'departments',
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true'))
    )

    # 2. Create revoked_tokens table
    op.create_table(
        'revoked_tokens',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('token_jti', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_revoked_tokens_token_jti'), 'revoked_tokens', ['token_jti'], unique=True)
    op.create_index(op.f('ix_revoked_tokens_user_id'), 'revoked_tokens', ['user_id'], unique=False)
    op.create_index(op.f('ix_revoked_tokens_expires_at'), 'revoked_tokens', ['expires_at'], unique=False)


def downgrade() -> None:
    op.drop_table('revoked_tokens')
    op.drop_column('departments', 'is_active')
