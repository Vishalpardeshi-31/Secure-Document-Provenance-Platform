"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-27 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. roles table
    op.create_table(
        'roles',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_roles_name'), 'roles', ['name'], unique=True)

    # 2. departments table
    op.create_table(
        'departments',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('code', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_departments_name'), 'departments', ['name'], unique=True)
    op.create_index(op.f('ix_departments_code'), 'departments', ['code'], unique=True)

    # 3. users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('role_id', sa.String(length=36), sa.ForeignKey('roles.id', ondelete='SET NULL'), nullable=True),
        sa.Column('department_id', sa.String(length=36), sa.ForeignKey('departments.id', ondelete='SET NULL'), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_role'), 'users', ['role'], unique=False)

    # 4. devices table
    op.create_table(
        'devices',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_name', sa.String(length=128), nullable=False),
        sa.Column('device_fingerprint', sa.String(length=255), nullable=False),
        sa.Column('registration_status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_devices_user_id'), 'devices', ['user_id'], unique=False)
    op.create_index(op.f('ix_devices_device_fingerprint'), 'devices', ['device_fingerprint'], unique=False)
    op.create_index(op.f('ix_devices_registration_status'), 'devices', ['registration_status'], unique=False)

    # 5. documents table
    op.create_table(
        'documents',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('classification', sa.String(length=32), nullable=False, server_default='RESTRICTED'),
        sa.Column('owner_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_documents_title'), 'documents', ['title'], unique=False)
    op.create_index(op.f('ix_documents_classification'), 'documents', ['classification'], unique=False)
    op.create_index(op.f('ix_documents_owner_id'), 'documents', ['owner_id'], unique=False)
    op.create_index(op.f('ix_documents_status'), 'documents', ['status'], unique=False)

    # 6. document_versions table
    op.create_table(
        'document_versions',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('encrypted_storage_reference', sa.String(length=512), nullable=False),
        sa.Column('content_hash', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('document_id', 'version_number', name='uq_document_version_number'),
    )
    op.create_index(op.f('ix_document_versions_document_id'), 'document_versions', ['document_id'], unique=False)
    op.create_index(op.f('ix_document_versions_content_hash'), 'document_versions', ['content_hash'], unique=False)

    # 7. document_recipients table
    op.create_table(
        'document_recipients',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('permission_level', sa.String(length=32), nullable=False, server_default='READ'),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('document_id', 'user_id', name='uq_document_recipient_user'),
    )
    op.create_index(op.f('ix_document_recipients_document_id'), 'document_recipients', ['document_id'], unique=False)
    op.create_index(op.f('ix_document_recipients_user_id'), 'document_recipients', ['user_id'], unique=False)

    # 8. access_policies table
    op.create_table(
        'access_policies',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('expiration_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('device_restriction', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('approval_requirement', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('maximum_sessions', sa.Integer(), nullable=True),
        sa.Column('one_time_decryption', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_access_policies_document_id'), 'access_policies', ['document_id'], unique=False)

    # 9. decryption_sessions table
    op.create_table(
        'decryption_sessions',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version_id', sa.String(length=36), sa.ForeignKey('document_versions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', sa.String(length=36), sa.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True),
        sa.Column('policy_id', sa.String(length=36), sa.ForeignKey('access_policies.id', ondelete='SET NULL'), nullable=True),
        sa.Column('session_token_hash', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='INITIATED'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(op.f('ix_decryption_sessions_document_id'), 'decryption_sessions', ['document_id'], unique=False)
    op.create_index(op.f('ix_decryption_sessions_version_id'), 'decryption_sessions', ['version_id'], unique=False)
    op.create_index(op.f('ix_decryption_sessions_user_id'), 'decryption_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_decryption_sessions_device_id'), 'decryption_sessions', ['device_id'], unique=False)
    op.create_index(op.f('ix_decryption_sessions_session_token_hash'), 'decryption_sessions', ['session_token_hash'], unique=False)
    op.create_index(op.f('ix_decryption_sessions_status'), 'decryption_sessions', ['status'], unique=False)

    # 10. audit_events table
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('session_id', sa.String(length=36), sa.ForeignKey('decryption_sessions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_hash', sa.String(length=128), nullable=False),
        sa.Column('previous_event_hash', sa.String(length=128), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
    )
    op.create_index(op.f('ix_audit_events_event_type'), 'audit_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_audit_events_user_id'), 'audit_events', ['user_id'], unique=False)
    op.create_index(op.f('ix_audit_events_document_id'), 'audit_events', ['document_id'], unique=False)
    op.create_index(op.f('ix_audit_events_session_id'), 'audit_events', ['session_id'], unique=False)
    op.create_index(op.f('ix_audit_events_timestamp'), 'audit_events', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('decryption_sessions')
    op.drop_table('access_policies')
    op.drop_table('document_recipients')
    op.drop_table('document_versions')
    op.drop_table('documents')
    op.drop_table('devices')
    op.drop_table('users')
    op.drop_table('departments')
    op.drop_table('roles')
