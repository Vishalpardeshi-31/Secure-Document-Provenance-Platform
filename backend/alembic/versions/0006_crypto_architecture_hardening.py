"""Hardening cryptographic key architecture: per-recipient DEK wrapping, versioning, Argon2id protection, and canonical AAD

Revision ID: 0006_crypto_hardening
Revises: 0005_access_policies_and_sessions
Create Date: 2026-09-28 00:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0006_crypto_hardening'
down_revision: Union[str, None] = '0005_access_policies_and_sessions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update documents table
    op.add_column('documents', sa.Column('key_management_version', sa.Integer(), nullable=False, server_default='2'))
    op.add_column('documents', sa.Column('protocol_version', sa.String(length=32), nullable=False, server_default='SDP-CRYPTO-V2'))

    # 2. Update recipient_keys table
    op.add_column('recipient_keys', sa.Column('kdf_algorithm', sa.String(length=32), nullable=False, server_default='Argon2id'))
    op.add_column('recipient_keys', sa.Column('kdf_salt', sa.String(length=64), nullable=True))
    op.add_column('recipient_keys', sa.Column('kdf_parameters', sa.Text(), nullable=True))
    op.add_column('recipient_keys', sa.Column('encryption_algorithm', sa.String(length=32), nullable=False, server_default='AES-256-GCM'))
    op.add_column('recipient_keys', sa.Column('encryption_nonce', sa.String(length=64), nullable=True))
    op.add_column('recipient_keys', sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True))

    # 3. Update document_recipients table
    op.add_column('document_recipients', sa.Column('recipient_key_id', sa.String(length=36), sa.ForeignKey('recipient_keys.id', ondelete='SET NULL'), nullable=True))
    op.add_column('document_recipients', sa.Column('kem_algorithm', sa.String(length=32), nullable=False, server_default='ML-KEM-768'))
    op.add_column('document_recipients', sa.Column('kem_ciphertext', sa.Text(), nullable=False, server_default=''))
    op.add_column('document_recipients', sa.Column('kdf_algorithm', sa.String(length=32), nullable=False, server_default='HKDF'))
    op.add_column('document_recipients', sa.Column('kdf_hash', sa.String(length=32), nullable=False, server_default='SHA-256'))
    op.add_column('document_recipients', sa.Column('kdf_info_version', sa.String(length=32), nullable=False, server_default='SDP-DEK-WRAP-v1'))
    op.add_column('document_recipients', sa.Column('wrap_algorithm', sa.String(length=32), nullable=False, server_default='AES-256-GCM'))
    op.add_column('document_recipients', sa.Column('wrap_nonce', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('document_recipients', sa.Column('protocol_version', sa.String(length=32), nullable=False, server_default='SDP-CRYPTO-V2'))
    op.create_index('ix_document_recipients_recipient_key_id', 'document_recipients', ['recipient_key_id'])


def downgrade() -> None:
    op.drop_index('ix_document_recipients_recipient_key_id', table_name='document_recipients')
    op.drop_column('document_recipients', 'protocol_version')
    op.drop_column('document_recipients', 'wrap_nonce')
    op.drop_column('document_recipients', 'wrap_algorithm')
    op.drop_column('document_recipients', 'kdf_info_version')
    op.drop_column('document_recipients', 'kdf_hash')
    op.drop_column('document_recipients', 'kdf_algorithm')
    op.drop_column('document_recipients', 'kem_ciphertext')
    op.drop_column('document_recipients', 'kem_algorithm')
    op.drop_column('document_recipients', 'recipient_key_id')

    op.drop_column('recipient_keys', 'activated_at')
    op.drop_column('recipient_keys', 'encryption_nonce')
    op.drop_column('recipient_keys', 'encryption_algorithm')
    op.drop_column('recipient_keys', 'kdf_parameters')
    op.drop_column('recipient_keys', 'kdf_salt')
    op.drop_column('recipient_keys', 'kdf_algorithm')

    op.drop_column('documents', 'protocol_version')
    op.drop_column('documents', 'key_management_version')
