"""Versions support multiple artifacts.

Revision ID: 3c7d9f4b2d91
Revises: 8dea867ad60e
Create Date: 2026-08-12 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "3c7d9f4b2d91"
down_revision: Union[str, Sequence[str], None] = "8dea867ad60e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("sms_artifacts", sa.Column("version_id", sa.String(length=36), nullable=True))
    op.create_index("ix_sms_artifacts_version_id", "sms_artifacts", ["version_id"], unique=False)
    op.create_index(
        "ix_sms_artifacts_version_id_status",
        "sms_artifacts",
        ["version_id", "status"],
        unique=False,
    )

    op.execute(
        """
        UPDATE sms_artifacts AS a
        SET version_id = v.id
        FROM sms_versions AS v
        WHERE v.artifact_id = a.id
        """
    )

    op.alter_column("sms_artifacts", "version_id", existing_type=sa.String(length=36), nullable=False)
    op.create_foreign_key(
        "fk_sms_artifacts_version_id_sms_versions",
        "sms_artifacts",
        "sms_versions",
        ["version_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("fk_sms_artifacts_version_id_sms_versions", "sms_artifacts", type_="foreignkey")
    op.drop_index("ix_sms_artifacts_version_id_status", table_name="sms_artifacts")
    op.drop_index("ix_sms_artifacts_version_id", table_name="sms_artifacts")
    op.drop_column("sms_artifacts", "version_id")
