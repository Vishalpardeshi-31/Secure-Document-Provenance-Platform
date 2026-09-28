"""add recipient keys and document recipient encapsulation columns

Revision ID: 0004_add_recipient_keys
Revises: 0003_add_document_encryption_metadata
Create Date: 2026-09-27 22:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0004_add_recipient_keys'
down_revision: Union[str, None] = '0003_add_document_encryption_metadata'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create recipient_keys table
    op.create_table(
        'recipient_keys',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('key_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('algorithm', sa.String(length=64), nullable=False, server_default='ML-KEM-768'),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('encrypted_private_key', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('user_id', 'key_version', name='uq_recipient_key_user_version'),
    )
    op.create_index('ix_recipient_keys_user_id', 'recipient_keys', ['user_id'])
    op.create_index('ix_recipient_keys_status', 'recipient_keys', ['status'])

    # 2. Add encapsulation columns to document_recipients
    op.add_column('document_recipients', sa.Column('recipient_key_version', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('document_recipients', sa.Column('key_algorithm', sa.String(length=64), nullable=False, server_default='ML-KEM-768+HKDF-SHA256+AES-256-GCM'))
    op.add_column('document_recipients', sa.Column('encapsulated_key', sa.Text(), nullable=False, server_default=''))
    op.add_column('document_recipients', sa.Column('wrapped_dek', sa.String(length=512), nullable=False, server_default=''))
    op.add_column('document_recipients', sa.Column('nonce', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('document_recipients', sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'))
    op.add_column('document_recipients', sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_document_recipients_status', 'document_recipients', ['status'])


def downgrade() -> None:
    op.drop_index('ix_document_recipients_status', table_name='document_recipients')
    op.drop_column('document_recipients', 'revoked_at')
    op.drop_column('document_recipients', 'status')
    op.drop_column('document_recipients', 'nonce')
    op.drop_column('document_recipients', 'wrapped_dek')
    op.drop_column('document_recipients', 'encapsulated_key')
    op.drop_column('document_recipients', 'key_algorithm')
    op.drop_column('document_recipients', 'recipient_key_version')

    op.drop_index('ix_recipient_keys_status', table_name='recipient_keys')
    op.drop_index('ix_recipient_keys_user_id', table_name='recipient_keys')
    op.drop_table('recipient_keys')
