"""Align security_alerts actor/ack user ids with the UUID user id format.

``actor_user_id`` is already ``VARCHAR(36)`` but
``acknowledged_by_user_id`` was declared as ``Integer``. User ids are UUIDs, so
acknowledging an alert could never store a real value, and the endpoint raised
instead. This widens the column to ``VARCHAR(36)`` to match ``actor_user_id``.

Revision ID: b1f7c9d40a21
Revises: 3c7d9f4b2d91
Create Date: 2026-09-28 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b1f7c9d40a21"
down_revision: Union[str, Sequence[str], None] = "3c7d9f4b2d91"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("security_alerts") as batch_op:
        batch_op.alter_column(
            "acknowledged_by_user_id",
            type_=sa.String(length=36),
            existing_type=sa.Integer(),
            postgresql_using="acknowledged_by_user_id::text",
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("security_alerts") as batch_op:
        batch_op.alter_column(
            "acknowledged_by_user_id",
            type_=sa.Integer(),
            existing_type=sa.String(length=36),
            postgresql_using="NULLIF(acknowledged_by_user_id, '')::integer",
            existing_nullable=True,
        )
