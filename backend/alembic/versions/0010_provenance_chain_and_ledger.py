"""Provenance hash chain and permissioned ledger outbox schema.

Revision ID: 0010_provenance_chain_and_ledger
Revises: 0009_cryptographic_provenance
Create Date: 2026-09-28 04:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0010_provenance_chain_and_ledger'
down_revision: Union[str, None] = '0009_cryptographic_provenance'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Alter provenance_records table to allow nullable document_id and user_id for genesis record
    with op.batch_alter_table('provenance_records') as batch_op:
        batch_op.alter_column('document_id', existing_type=sa.String(length=36), nullable=True)
        batch_op.alter_column('user_id', existing_type=sa.String(length=36), nullable=True)
        batch_op.alter_column('document_version_id', existing_type=sa.String(length=36), nullable=True)
        batch_op.alter_column('decryption_session_id', existing_type=sa.String(length=36), nullable=True)
        batch_op.alter_column('policy_id', existing_type=sa.String(length=36), nullable=True)
        batch_op.alter_column('policy_version', existing_type=sa.Integer(), nullable=True)

        # Add chain fields
        batch_op.add_column(sa.Column('chain_id', sa.String(length=64), nullable=False, server_default='PLATFORM-PROVENANCE-CHAIN'))
        batch_op.add_column(sa.Column('chain_sequence', sa.Integer(), nullable=False, server_default='1'))
        batch_op.add_column(sa.Column('previous_record_hash', sa.String(length=64), nullable=False, server_default='0'*64))
        batch_op.add_column(sa.Column('chain_hash', sa.String(length=64), nullable=False, server_default='0'*64))
        batch_op.add_column(sa.Column('chain_version', sa.Integer(), nullable=False, server_default='1'))

        # Add ledger fields
        batch_op.add_column(sa.Column('ledger_transaction_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('ledger_status', sa.String(length=32), nullable=False, server_default='PENDING'))
        batch_op.add_column(sa.Column('ledger_record_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('ledger_anchored_at', sa.DateTime(timezone=True), nullable=True))

        # Add unique constraints
        batch_op.create_unique_constraint('uq_provenance_chain_sequence', ['chain_id', 'chain_sequence'])
        batch_op.create_unique_constraint('uq_provenance_chain_hash', ['chain_id', 'chain_hash'])
        batch_op.create_index('ix_provenance_records_chain_id', ['chain_id'])
        batch_op.create_index('ix_provenance_records_chain_sequence', ['chain_sequence'])
        batch_op.create_index('ix_provenance_records_chain_hash', ['chain_hash'])
        batch_op.create_index('ix_provenance_records_ledger_transaction_id', ['ledger_transaction_id'])
        batch_op.create_index('ix_provenance_records_ledger_status', ['ledger_status'])

    # 2. Create provenance_chain_heads table
    op.create_table(
        'provenance_chain_heads',
        sa.Column('chain_id', sa.String(length=64), primary_key=True),
        sa.Column('latest_sequence', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('latest_chain_hash', sa.String(length=64), nullable=False),
        sa.Column('genesis_hash', sa.String(length=64), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 3. Create ledger_outbox table
    op.create_table(
        'ledger_outbox',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('outbox_id', sa.String(length=36), nullable=False),
        sa.Column('event_id', sa.String(length=36), nullable=False),
        sa.Column('chain_id', sa.String(length=64), nullable=False),
        sa.Column('chain_sequence', sa.Integer(), nullable=False),
        sa.Column('chain_hash', sa.String(length=64), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('attempt_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_attempt_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('outbox_id', name='uq_ledger_outbox_id'),
    )
    op.create_index('ix_ledger_outbox_event_id', 'ledger_outbox', ['event_id'])
    op.create_index('ix_ledger_outbox_chain_id', 'ledger_outbox', ['chain_id'])
    op.create_index('ix_ledger_outbox_status', 'ledger_outbox', ['status'])


def downgrade() -> None:
    op.drop_table('ledger_outbox')
    op.drop_table('provenance_chain_heads')
    with op.batch_alter_table('provenance_records') as batch_op:
        batch_op.drop_index('ix_provenance_records_ledger_status')
        batch_op.drop_index('ix_provenance_records_ledger_transaction_id')
        batch_op.drop_index('ix_provenance_records_chain_hash')
        batch_op.drop_index('ix_provenance_records_chain_sequence')
        batch_op.drop_index('ix_provenance_records_chain_id')
        batch_op.drop_constraint('uq_provenance_chain_hash', type_='unique')
        batch_op.drop_constraint('uq_provenance_chain_sequence', type_='unique')
        batch_op.drop_column('ledger_anchored_at')
        batch_op.drop_column('ledger_record_hash')
        batch_op.drop_column('ledger_status')
        batch_op.drop_column('ledger_transaction_id')
        batch_op.drop_column('chain_version')
        batch_op.drop_column('chain_hash')
        batch_op.drop_column('previous_record_hash')
        batch_op.drop_column('chain_sequence')
        batch_op.drop_column('chain_id')
