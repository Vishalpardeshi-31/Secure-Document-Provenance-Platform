"""Secure Document Viewer Sessions schema.

Revision ID: 0011_secure_viewer_sessions
Revises: 0010_provenance_chain_and_ledger
Create Date: 2026-09-28 04:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0011_secure_viewer_sessions'
down_revision: Union[str, None] = '0010_provenance_chain_and_ledger'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'viewer_sessions',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('decryption_session_id', sa.String(length=36), sa.ForeignKey('decryption_sessions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('provenance_event_id', sa.String(length=36), nullable=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('document_version_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', sa.String(length=36), sa.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('session_duration_seconds', sa.Integer(), nullable=False, server_default='900'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_viewer_sessions_decryption_session_id', 'viewer_sessions', ['decryption_session_id'])
    op.create_index('ix_viewer_sessions_provenance_event_id', 'viewer_sessions', ['provenance_event_id'])
    op.create_index('ix_viewer_sessions_document_id', 'viewer_sessions', ['document_id'])
    op.create_index('ix_viewer_sessions_user_id', 'viewer_sessions', ['user_id'])
    op.create_index('ix_viewer_sessions_device_id', 'viewer_sessions', ['device_id'])
    op.create_index('ix_viewer_sessions_status', 'viewer_sessions', ['status'])
    op.create_index('ix_viewer_sessions_expires_at', 'viewer_sessions', ['expires_at'])


def downgrade() -> None:
    op.drop_index('ix_viewer_sessions_expires_at', table_name='viewer_sessions')
    op.drop_index('ix_viewer_sessions_status', table_name='viewer_sessions')
    op.drop_index('ix_viewer_sessions_device_id', table_name='viewer_sessions')
    op.drop_index('ix_viewer_sessions_user_id', table_name='viewer_sessions')
    op.drop_index('ix_viewer_sessions_document_id', table_name='viewer_sessions')
    op.drop_index('ix_viewer_sessions_provenance_event_id', table_name='viewer_sessions')
    op.drop_index('ix_viewer_sessions_decryption_session_id', table_name='viewer_sessions')
    op.drop_table('viewer_sessions')
