"""add document encryption metadata columns

Revision ID: 0003_add_document_encryption_metadata
Revises: 0002_add_revoked_tokens
Create Date: 2026-09-27 18:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003_add_document_encryption_metadata'
down_revision: Union[str, None] = '0002_add_revoked_tokens'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('documents', sa.Column('original_filename', sa.String(length=255), nullable=False, server_default=''))
    op.add_column('documents', sa.Column('mime_type', sa.String(length=128), nullable=False, server_default='application/octet-stream'))
    op.add_column('documents', sa.Column('original_size_bytes', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('documents', sa.Column('encrypted_size_bytes', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('documents', sa.Column('storage_reference', sa.String(length=512), nullable=False, server_default=''))
    op.add_column('documents', sa.Column('plaintext_sha256', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('documents', sa.Column('ciphertext_sha256', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('documents', sa.Column('encryption_algorithm', sa.String(length=64), nullable=False, server_default='AES-256-GCM'))
    op.add_column('documents', sa.Column('key_encryption_algorithm', sa.String(length=64), nullable=False, server_default='AES-256-GCM-KEK'))
    op.add_column('documents', sa.Column('nonce', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('documents', sa.Column('encrypted_dek', sa.String(length=512), nullable=False, server_default=''))


def downgrade() -> None:
    op.drop_column('documents', 'encrypted_dek')
    op.drop_column('documents', 'nonce')
    op.drop_column('documents', 'key_encryption_algorithm')
    op.drop_column('documents', 'encryption_algorithm')
    op.drop_column('documents', 'ciphertext_sha256')
    op.drop_column('documents', 'plaintext_sha256')
    op.drop_column('documents', 'storage_reference')
    op.drop_column('documents', 'encrypted_size_bytes')
    op.drop_column('documents', 'original_size_bytes')
    op.drop_column('documents', 'mime_type')
    op.drop_column('documents', 'original_filename')
