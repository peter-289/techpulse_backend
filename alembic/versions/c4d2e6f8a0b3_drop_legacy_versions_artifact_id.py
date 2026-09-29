"""Drop the legacy ``sms_versions.artifact_id`` column.

The initial revision modelled a version as owning at most one artifact via
``sms_versions.artifact_id``. Revision ``3c7d9f4b2d91`` inverted the
relationship to ``sms_artifacts.version_id`` (a version owns many artifacts) and
backfilled it with::

    UPDATE sms_artifacts AS a
       SET version_id = v.id
      FROM sms_versions AS v
     WHERE v.artifact_id = a.id

but never dropped the old column, so the schema still carried a ``VARCHAR(36)``
column, a ``UNIQUE`` constraint and an ``ON DELETE SET NULL`` foreign key that no
model declares. ``alembic check`` reported all three as removable drift.

The data is safe to discard: the same revision that backfilled
``sms_artifacts.version_id`` also altered it to ``NOT NULL``. That could only
have succeeded if every artifact received a version, i.e. the backfill was
total and the direction of the old column is fully represented by the new one.

Revision ID: c4d2e6f8a0b3
Revises: b1f7c9d40a21
Create Date: 2026-09-28 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c4d2e6f8a0b3"
down_revision: Union[str, Sequence[str], None] = "b1f7c9d40a21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "sms_versions_artifact_id_fkey",
        "sms_versions",
        type_="foreignkey",
    )
    op.drop_constraint(
        "sms_versions_artifact_id_key",
        "sms_versions",
        type_="unique",
    )
    op.drop_column("sms_versions", "artifact_id")


def downgrade() -> None:
    with op.batch_alter_table("sms_versions") as batch_op:
        batch_op.add_column(sa.Column("artifact_id", sa.String(length=36), nullable=True))
    op.create_foreign_key(
        "sms_versions_artifact_id_fkey",
        "sms_versions",
        "sms_artifacts",
        ["artifact_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_unique_constraint(
        "sms_versions_artifact_id_key",
        "sms_versions",
        ["artifact_id"],
    )
