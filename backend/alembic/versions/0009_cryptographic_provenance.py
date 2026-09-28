"""Cryptographic provenance records and ML-DSA signing keys schema.

Revision ID: 0009_cryptographic_provenance
Revises: 0008_approval_and_emergency
Create Date: 2026-09-28 03:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0009_cryptographic_provenance'
down_revision: Union[str, None] = '0008_approval_and_emergency'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create provenance_signing_keys table
    op.create_table(
        'provenance_signing_keys',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('key_version', sa.Integer(), nullable=False),
        sa.Column('algorithm', sa.String(length=32), nullable=False, server_default='ML-DSA-65'),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('encrypted_private_key', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('key_version', name='uq_provenance_signing_keys_version'),
    )
    op.create_index('ix_provenance_signing_keys_key_version', 'provenance_signing_keys', ['key_version'])
    op.create_index('ix_provenance_signing_keys_status', 'provenance_signing_keys', ['status'])

    # 2. Create provenance_records table
    op.create_table(
        'provenance_records',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('event_id', sa.String(length=36), nullable=False),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('document_version_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('recipient_key_id', sa.String(length=36), nullable=True),
        sa.Column('recipient_key_version', sa.Integer(), nullable=True),
        sa.Column('device_id', sa.String(length=36), nullable=True),
        sa.Column('decryption_session_id', sa.String(length=36), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('policy_version', sa.Integer(), nullable=False),
        sa.Column('access_type', sa.String(length=32), nullable=False, server_default='NORMAL'),
        sa.Column('approval_request_id', sa.String(length=36), nullable=True),
        sa.Column('emergency_access_request_id', sa.String(length=36), nullable=True),
        sa.Column('document_plaintext_sha256', sa.String(length=64), nullable=False),
        sa.Column('document_ciphertext_sha256', sa.String(length=64), nullable=False),
        sa.Column('event_timestamp', sa.String(length=32), nullable=False),
        sa.Column('protocol_version', sa.String(length=32), nullable=False, server_default='PROVENANCE-V1'),
        sa.Column('provenance_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('canonical_record_hash', sa.String(length=64), nullable=False),
        sa.Column('signature_algorithm', sa.String(length=32), nullable=False, server_default='ML-DSA-65'),
        sa.Column('signature_key_id', sa.String(length=36), nullable=False),
        sa.Column('signature_key_version', sa.Integer(), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('event_id', name='uq_provenance_records_event_id'),
    )
    op.create_index('ix_provenance_records_event_id', 'provenance_records', ['event_id'])
    op.create_index('ix_provenance_records_document_id', 'provenance_records', ['document_id'])
    op.create_index('ix_provenance_records_document_version_id', 'provenance_records', ['document_version_id'])
    op.create_index('ix_provenance_records_user_id', 'provenance_records', ['user_id'])
    op.create_index('ix_provenance_records_decryption_session_id', 'provenance_records', ['decryption_session_id'])
    op.create_index('ix_provenance_records_access_type', 'provenance_records', ['access_type'])


def downgrade() -> None:
    op.drop_table('provenance_records')
    op.drop_table('provenance_signing_keys')
