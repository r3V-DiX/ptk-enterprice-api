"""key_prefix resize to 16 + scan_quota_per_month on api_keys

Revision ID: a1b2c3d4e5f6
Revises: 219d3a207b8f
Create Date: 2026-07-29
"""
from alembic import op
import sqlalchemy as sa

revision = 'a1b2c3d4e5f6'
down_revision = '219d3a207b8f'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Widen key_prefix: ptk_live_XXXXX = 14 chars; 16 gives headroom
    op.alter_column(
        'api_keys', 'key_prefix',
        existing_type=sa.String(length=12),
        type_=sa.String(length=16),
        existing_nullable=False,
    )
    # Monthly scan quota — NULL means unlimited
    op.add_column(
        'api_keys',
        sa.Column('scan_quota_per_month', sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('api_keys', 'scan_quota_per_month')
    op.alter_column(
        'api_keys', 'key_prefix',
        existing_type=sa.String(length=16),
        type_=sa.String(length=12),
        existing_nullable=False,
    )
