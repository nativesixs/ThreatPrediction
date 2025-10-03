"""add_v7_fields_to_predictions

Revision ID: 75e5e77f51a2
Revises: 001
Create Date: 2025-10-02 17:08:45.418154

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '75e5e77f51a2'
down_revision: Union[str, Sequence[str], None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - add v7 model integration fields."""
    # Add model_version field
    op.add_column('predictions', sa.Column('model_version', sa.String(length=20), nullable=True))
    
    # Add is_confident field (whether confidence threshold was met)
    op.add_column('predictions', sa.Column('is_confident', sa.Boolean(), nullable=True, server_default=sa.true()))
    
    # Add severity field (CRITICAL, HIGH, MEDIUM, BENIGN)
    op.add_column('predictions', sa.Column('severity', sa.String(length=20), nullable=True))


def downgrade() -> None:
    """Downgrade schema - remove v7 model integration fields."""
    op.drop_column('predictions', 'severity')
    op.drop_column('predictions', 'is_confident')
    op.drop_column('predictions', 'model_version')
