"""sms version lifecycle + idempotency

Revision ID: 20260320_0008
Revises: 20260304_0007
Create Date: 2026-03-20 12:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260320_0008"
down_revision: Union[str, None] = "20260304_0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_sqlite() -> bool:
    bind = op.get_bind()
    return bind.dialect.name == "sqlite"


def upgrade() -> None:
    if _is_sqlite():
        with op.batch_alter_table("sms_softwares", recreate="auto") as batch_op:
            batch_op.add_column(sa.Column("current_version_id", sa.Uuid(), nullable=True))
            batch_op.create_foreign_key(
                "fk_sms_softwares_current_version",
                "sms_versions",
                ["current_version_id"],
                ["id"],
                ondelete="SET NULL",
            )
            batch_op.create_index(
                "ix_sms_softwares_current_version_id",
                ["current_version_id"],
                unique=False,
            )

        with op.batch_alter_table("sms_versions", recreate="auto") as batch_op:
            batch_op.add_column(
                sa.Column("status", sa.String(length=16), server_default="DRAFT", nullable=False)
            )
            batch_op.add_column(sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True))
            batch_op.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
            batch_op.create_index("ix_sms_versions_status", ["status"], unique=False)
            batch_op.create_check_constraint(
                "ck_sms_versions_status",
                "status IN ('DRAFT', 'PUBLISHED', 'DEPRECATED', 'REVOKED')",
            )
    else:
        op.add_column(
            "sms_softwares",
            sa.Column("current_version_id", sa.Uuid(), nullable=True),
        )
        op.create_foreign_key(
            "fk_sms_softwares_current_version",
            "sms_softwares",
            "sms_versions",
            ["current_version_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_index(
            "ix_sms_softwares_current_version_id",
            "sms_softwares",
            ["current_version_id"],
            unique=False,
        )

        op.add_column(
            "sms_versions",
            sa.Column("status", sa.String(length=16), server_default="DRAFT", nullable=False),
        )
        op.add_column("sms_versions", sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True))
        op.add_column("sms_versions", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        op.create_index("ix_sms_versions_status", "sms_versions", ["status"], unique=False)
        op.create_check_constraint(
            "ck_sms_versions_status",
            "sms_versions",
            "status IN ('DRAFT', 'PUBLISHED', 'DEPRECATED', 'REVOKED')",
        )

    op.execute(
        """
        UPDATE sms_versions
        SET status = CASE
            WHEN is_published IS TRUE THEN 'PUBLISHED'
            ELSE 'DRAFT'
        END
        """
    )

    op.execute(
        """
        UPDATE sms_softwares
        SET current_version_id = (
            SELECT v.id
            FROM sms_versions v
            WHERE v.software_id = sms_softwares.id
              AND v.is_published IS TRUE
            ORDER BY v.published_at DESC, v.created_at DESC
            LIMIT 1
        )
        """
    )

    op.create_table(
        "sms_idempotency_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scope", "actor_id", "key", name="uq_sms_idempotency_scope_actor_key"),
    )
    op.create_index(
        "ix_sms_idempotency_scope_actor",
        "sms_idempotency_keys",
        ["scope", "actor_id"],
        unique=False,
    )
    op.create_index(
        "ix_sms_idempotency_created_at",
        "sms_idempotency_keys",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_sms_idempotency_created_at", table_name="sms_idempotency_keys")
    op.drop_index("ix_sms_idempotency_scope_actor", table_name="sms_idempotency_keys")
    op.drop_table("sms_idempotency_keys")

    if _is_sqlite():
        with op.batch_alter_table("sms_versions", recreate="auto") as batch_op:
            batch_op.drop_constraint("ck_sms_versions_status", type_="check")
            batch_op.drop_index("ix_sms_versions_status")
            batch_op.drop_column("revoked_at")
            batch_op.drop_column("deprecated_at")
            batch_op.drop_column("status")

        with op.batch_alter_table("sms_softwares", recreate="auto") as batch_op:
            batch_op.drop_index("ix_sms_softwares_current_version_id")
            batch_op.drop_constraint("fk_sms_softwares_current_version", type_="foreignkey")
            batch_op.drop_column("current_version_id")
    else:
        op.drop_constraint("ck_sms_versions_status", "sms_versions", type_="check")
        op.drop_index("ix_sms_versions_status", table_name="sms_versions")
        op.drop_column("sms_versions", "revoked_at")
        op.drop_column("sms_versions", "deprecated_at")
        op.drop_column("sms_versions", "status")

        op.drop_index("ix_sms_softwares_current_version_id", table_name="sms_softwares")
        op.drop_constraint("fk_sms_softwares_current_version", "sms_softwares", type_="foreignkey")
        op.drop_column("sms_softwares", "current_version_id")
