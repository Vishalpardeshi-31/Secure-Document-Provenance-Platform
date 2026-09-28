"""Forensic Fingerprints schema.

Revision ID: 0012_forensic_fingerprints
Revises: 0011_secure_viewer_sessions
Create Date: 2026-09-28 07:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0012_forensic_fingerprints'
down_revision: Union[str, None] = '0011_secure_viewer_sessions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'forensic_fingerprints',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('document_version_id', sa.String(length=36), nullable=False),
        sa.Column('provenance_event_id', sa.String(length=36), nullable=False),
        sa.Column('decryption_session_id', sa.String(length=36), sa.ForeignKey('decryption_sessions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('viewer_session_id', sa.String(length=36), sa.ForeignKey('viewer_sessions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('recipient_user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('recipient_key_id', sa.String(length=36), nullable=True),
        sa.Column('fingerprint_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('fingerprint_algorithm', sa.String(length=64), nullable=False, server_default='HKDF-SHA256-DSSS-DCT'),
        sa.Column('fingerprint_token', sa.String(length=32), nullable=False, unique=True),
        sa.Column('fingerprint_commitment', sa.String(length=64), nullable=False, unique=True),
        sa.Column('fingerprint_nonce', sa.String(length=64), nullable=False),
        sa.Column('embedding_profile', sa.String(length=64), nullable=False, server_default='PDF_DCT_SPREAD_SPECTRUM_V1'),
        sa.Column('embedding_parameters_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_forensic_fingerprints_document_id', 'forensic_fingerprints', ['document_id'])
    op.create_index('ix_forensic_fingerprints_document_version_id', 'forensic_fingerprints', ['document_version_id'])
    op.create_index('ix_forensic_fingerprints_provenance_event_id', 'forensic_fingerprints', ['provenance_event_id'])
    op.create_index('ix_forensic_fingerprints_decryption_session_id', 'forensic_fingerprints', ['decryption_session_id'])
    op.create_index('ix_forensic_fingerprints_viewer_session_id', 'forensic_fingerprints', ['viewer_session_id'])
    op.create_index('ix_forensic_fingerprints_recipient_user_id', 'forensic_fingerprints', ['recipient_user_id'])
    op.create_index('ix_forensic_fingerprints_recipient_key_id', 'forensic_fingerprints', ['recipient_key_id'])
    op.create_index('ix_forensic_fingerprints_fingerprint_token', 'forensic_fingerprints', ['fingerprint_token'])
    op.create_index('ix_forensic_fingerprints_fingerprint_commitment', 'forensic_fingerprints', ['fingerprint_commitment'])
    op.create_index('ix_forensic_fingerprints_status', 'forensic_fingerprints', ['status'])


def downgrade() -> None:
    op.drop_table('forensic_fingerprints')
