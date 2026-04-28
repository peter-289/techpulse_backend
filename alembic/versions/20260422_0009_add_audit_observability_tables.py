"""add audit observability tables

Revision ID: 20260422_0009
Revises: 20260320_0008
Create Date: 2026-04-22 17:10:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260422_0009"
down_revision: Union[str, None] = "20260320_0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(table_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _index_exists(table_name: str, index_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    indexes = inspector.get_indexes(table_name)
    return any(idx.get("name") == index_name for idx in indexes)


def upgrade() -> None:
    if not _table_exists("audit_events"):
        op.create_table(
            "audit_events",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("event_type", sa.String(length=120), nullable=False),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("method", sa.String(length=10), nullable=False),
            sa.Column("path", sa.String(length=255), nullable=False),
            sa.Column("status_code", sa.Integer(), nullable=False),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("user_agent", sa.String(length=255), nullable=True),
            sa.Column("request_id", sa.String(length=64), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=True),
            sa.Column(
                "occurred_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _index_exists("audit_events", "ix_audit_events_occurred_at"):
        op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"], unique=False)
    if not _index_exists("audit_events", "ix_audit_events_type_occurred"):
        op.create_index(
            "ix_audit_events_type_occurred",
            "audit_events",
            ["event_type", "occurred_at"],
            unique=False,
        )
    if not _index_exists("audit_events", "ix_audit_events_actor_occurred"):
        op.create_index(
            "ix_audit_events_actor_occurred",
            "audit_events",
            ["actor_user_id", "occurred_at"],
            unique=False,
        )
    if not _index_exists("audit_events", "ix_audit_events_ip_occurred"):
        op.create_index(
            "ix_audit_events_ip_occurred",
            "audit_events",
            ["ip_address", "occurred_at"],
            unique=False,
        )

    if not _table_exists("security_alerts"):
        op.create_table(
            "security_alerts",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("rule_code", sa.String(length=120), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("audit_event_id", sa.Integer(), nullable=True),
            sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("acknowledged_by_user_id", sa.Integer(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["audit_event_id"], ["audit_events.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _index_exists("security_alerts", "ix_security_alerts_created_at"):
        op.create_index("ix_security_alerts_created_at", "security_alerts", ["created_at"], unique=False)
    if not _index_exists("security_alerts", "ix_security_alerts_rule_created"):
        op.create_index(
            "ix_security_alerts_rule_created",
            "security_alerts",
            ["rule_code", "created_at"],
            unique=False,
        )
    if not _index_exists("security_alerts", "ix_security_alerts_ack_created"):
        op.create_index(
            "ix_security_alerts_ack_created",
            "security_alerts",
            ["acknowledged", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    if _table_exists("security_alerts"):
        if _index_exists("security_alerts", "ix_security_alerts_ack_created"):
            op.drop_index("ix_security_alerts_ack_created", table_name="security_alerts")
        if _index_exists("security_alerts", "ix_security_alerts_rule_created"):
            op.drop_index("ix_security_alerts_rule_created", table_name="security_alerts")
        if _index_exists("security_alerts", "ix_security_alerts_created_at"):
            op.drop_index("ix_security_alerts_created_at", table_name="security_alerts")
        op.drop_table("security_alerts")

    if _table_exists("audit_events"):
        if _index_exists("audit_events", "ix_audit_events_ip_occurred"):
            op.drop_index("ix_audit_events_ip_occurred", table_name="audit_events")
        if _index_exists("audit_events", "ix_audit_events_actor_occurred"):
            op.drop_index("ix_audit_events_actor_occurred", table_name="audit_events")
        if _index_exists("audit_events", "ix_audit_events_type_occurred"):
            op.drop_index("ix_audit_events_type_occurred", table_name="audit_events")
        if _index_exists("audit_events", "ix_audit_events_occurred_at"):
            op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
        op.drop_table("audit_events")
