"""Multi-party approval and emergency break-glass access schema.

Revision ID: 0008_approval_and_emergency
Revises: 0007_policy_hardening
Create Date: 2026-09-28 02:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0008_approval_and_emergency'
down_revision: Union[str, None] = '0007_policy_hardening'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update access_policies table with multi-party approval and emergency configuration
    op.add_column('access_policies', sa.Column('require_multi_party_approval', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('access_policies', sa.Column('required_approvals', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('access_policies', sa.Column('eligible_approver_roles', sa.String(length=255), nullable=True))
    op.add_column('access_policies', sa.Column('allow_emergency_access', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('access_policies', sa.Column('eligible_emergency_roles', sa.String(length=255), nullable=True))
    op.add_column('access_policies', sa.Column('eligible_emergency_permission', sa.String(length=64), nullable=True, server_default='EMERGENCY_DECRYPT'))
    op.add_column('access_policies', sa.Column('emergency_approval_required', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('access_policies', sa.Column('maximum_emergency_duration', sa.Integer(), nullable=False, server_default='15'))

    # 2. Update users table with emergency privilege flag
    op.add_column('users', sa.Column('can_emergency_decrypt', sa.Boolean(), nullable=False, server_default=sa.text('false')))

    # 3. Create approval_requests table
    op.create_table(
        'approval_requests',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('requesting_user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('decryption_session_id', sa.String(length=36), sa.ForeignKey('decryption_sessions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('policy_id', sa.String(length=36), sa.ForeignKey('access_policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('policy_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('required_approvals', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_approval_requests_document_id', 'approval_requests', ['document_id'])
    op.create_index('ix_approval_requests_requesting_user_id', 'approval_requests', ['requesting_user_id'])
    op.create_index('ix_approval_requests_policy_id', 'approval_requests', ['policy_id'])
    op.create_index('ix_approval_requests_status', 'approval_requests', ['status'])

    # 4. Create approval_records table
    op.create_table(
        'approval_records',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('approval_request_id', sa.String(length=36), sa.ForeignKey('approval_requests.id', ondelete='CASCADE'), nullable=False),
        sa.Column('approver_user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('approver_role', sa.String(length=32), nullable=False),
        sa.Column('decision', sa.String(length=16), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('approval_request_id', 'approver_user_id', name='uq_approval_request_approver'),
    )
    op.create_index('ix_approval_records_approval_request_id', 'approval_records', ['approval_request_id'])
    op.create_index('ix_approval_records_approver_user_id', 'approval_records', ['approver_user_id'])

    # 5. Create emergency_access_requests table
    op.create_table(
        'emergency_access_requests',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('document_id', sa.String(length=36), sa.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('requester_user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('requester_role', sa.String(length=32), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='REQUESTED'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approver_user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
    )
    op.create_index('ix_emergency_access_requests_document_id', 'emergency_access_requests', ['document_id'])
    op.create_index('ix_emergency_access_requests_requester_user_id', 'emergency_access_requests', ['requester_user_id'])
    op.create_index('ix_emergency_access_requests_status', 'emergency_access_requests', ['status'])


def downgrade() -> None:
    op.drop_table('emergency_access_requests')
    op.drop_table('approval_records')
    op.drop_table('approval_requests')
    op.drop_column('users', 'can_emergency_decrypt')
    op.drop_column('access_policies', 'maximum_emergency_duration')
    op.drop_column('access_policies', 'emergency_approval_required')
    op.drop_column('access_policies', 'eligible_emergency_permission')
    op.drop_column('access_policies', 'eligible_emergency_roles')
    op.drop_column('access_policies', 'allow_emergency_access')
    op.drop_column('access_policies', 'eligible_approver_roles')
    op.drop_column('access_policies', 'required_approvals')
    op.drop_column('access_policies', 'require_multi_party_approval')
