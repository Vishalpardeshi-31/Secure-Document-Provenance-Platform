"""Investigation cases, evidence, custody, and results schema.

Revision ID: 0013_investigation_cases
Revises: 0012_forensic_fingerprints
Create Date: 2026-09-28 07:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0013_investigation_cases'
down_revision: Union[str, None] = '0012_forensic_fingerprints'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. investigation_cases
    op.create_table(
        'investigation_cases',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('case_reference', sa.String(length=64), nullable=False, unique=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('document_version_id', sa.String(length=36), nullable=True),
        sa.Column('evidence_filename', sa.String(length=255), nullable=True),
        sa.Column('evidence_sha256', sa.String(length=64), nullable=True),
        sa.Column('evidence_size', sa.Integer(), nullable=True),
        sa.Column('evidence_mime_type', sa.String(length=128), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_investigation_cases_case_reference', 'investigation_cases', ['case_reference'])
    op.create_index('ix_investigation_cases_created_by', 'investigation_cases', ['created_by'])
    op.create_index('ix_investigation_cases_document_id', 'investigation_cases', ['document_id'])
    op.create_index('ix_investigation_cases_evidence_sha256', 'investigation_cases', ['evidence_sha256'])
    op.create_index('ix_investigation_cases_status', 'investigation_cases', ['status'])

    # 2. investigation_evidence
    op.create_table(
        'investigation_evidence',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('investigation_cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('mime_type', sa.String(length=128), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('storage_reference', sa.String(length=512), nullable=False),
        sa.Column('uploaded_by', sa.String(length=36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('uploaded_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('evidence_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('processing_status', sa.String(length=32), nullable=False, server_default='PENDING'),
    )
    op.create_index('ix_investigation_evidence_case_id', 'investigation_evidence', ['case_id'])
    op.create_index('ix_investigation_evidence_sha256', 'investigation_evidence', ['sha256'])
    op.create_index('ix_investigation_evidence_uploaded_by', 'investigation_evidence', ['uploaded_by'])
    op.create_index('ix_investigation_evidence_processing_status', 'investigation_evidence', ['processing_status'])

    # 3. investigation_custody_events
    op.create_table(
        'investigation_custody_events',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('investigation_cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(length=36), sa.ForeignKey('investigation_evidence.id', ondelete='CASCADE'), nullable=True),
        sa.Column('actor_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('evidence_sha256', sa.String(length=64), nullable=True),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_investigation_custody_events_case_id', 'investigation_custody_events', ['case_id'])
    op.create_index('ix_investigation_custody_events_evidence_id', 'investigation_custody_events', ['evidence_id'])
    op.create_index('ix_investigation_custody_events_actor_id', 'investigation_custody_events', ['actor_id'])
    op.create_index('ix_investigation_custody_events_action', 'investigation_custody_events', ['action'])

    # 4. investigation_results
    op.create_table(
        'investigation_results',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('case_id', sa.String(length=36), sa.ForeignKey('investigation_cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(length=36), sa.ForeignKey('investigation_evidence.id', ondelete='CASCADE'), nullable=False),
        sa.Column('detection_status', sa.String(length=64), nullable=False),
        sa.Column('fingerprint_id', sa.String(length=36), sa.ForeignKey('forensic_fingerprints.id', ondelete='SET NULL'), nullable=True),
        sa.Column('provenance_event_id', sa.String(length=64), nullable=True),
        sa.Column('provenance_signature_status', sa.String(length=32), nullable=True),
        sa.Column('chain_verification_status', sa.String(length=32), nullable=True),
        sa.Column('ledger_verification_status', sa.String(length=32), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('analyzed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('analyzer_version', sa.String(length=32), nullable=False, server_default='FORENSIC-V12'),
        sa.Column('result_summary', sa.Text(), nullable=False),
        sa.Column('limitations', sa.Text(), nullable=False),
        sa.Column('details_json', sa.Text(), nullable=True),
    )
    op.create_index('ix_investigation_results_case_id', 'investigation_results', ['case_id'])
    op.create_index('ix_investigation_results_evidence_id', 'investigation_results', ['evidence_id'])
    op.create_index('ix_investigation_results_detection_status', 'investigation_results', ['detection_status'])
    op.create_index('ix_investigation_results_fingerprint_id', 'investigation_results', ['fingerprint_id'])


def downgrade() -> None:
    op.drop_table('investigation_results')
    op.drop_table('investigation_custody_events')
    op.drop_table('investigation_evidence')
    op.drop_table('investigation_cases')
