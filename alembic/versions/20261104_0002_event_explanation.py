"""Persist on-demand SHAP evidence with its existing detection event."""

from alembic import op
import sqlalchemy as sa

revision = "20261104_0002"
down_revision = "20261104_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("detection_events", sa.Column("explanation_data", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("detection_events", "explanation_data")
