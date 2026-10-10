"""Persist historical artifact security scan reports.

Revision ID: d7e8f9a0b1c2
Revises: c4d2e6f8a0b3
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d7e8f9a0b1c2"
down_revision: Union[str, Sequence[str], None] = "c4d2e6f8a0b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_scan_reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("software_id", sa.String(length=36), nullable=False),
        sa.Column("version_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("reference", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["artifact_id"], ["sms_artifacts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["software_id"], ["sms_softwares.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["version_id"], ["sms_versions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_scan_reports_artifact_id", "security_scan_reports", ["artifact_id"])
    op.create_index("ix_security_scan_reports_software_id", "security_scan_reports", ["software_id"])
    op.create_index("ix_security_scan_reports_version_id", "security_scan_reports", ["version_id"])
    op.create_index(
        "ix_security_scan_reports_artifact_requested",
        "security_scan_reports",
        ["artifact_id", "requested_at"],
    )
    op.create_index(
        "ix_security_scan_reports_software_requested",
        "security_scan_reports",
        ["software_id", "requested_at"],
    )
    op.create_index(
        "ix_security_scan_reports_status_verdict",
        "security_scan_reports",
        ["status", "verdict"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_scan_reports_status_verdict", table_name="security_scan_reports")
    op.drop_index("ix_security_scan_reports_software_requested", table_name="security_scan_reports")
    op.drop_index("ix_security_scan_reports_artifact_requested", table_name="security_scan_reports")
    op.drop_index("ix_security_scan_reports_version_id", table_name="security_scan_reports")
    op.drop_index("ix_security_scan_reports_software_id", table_name="security_scan_reports")
    op.drop_index("ix_security_scan_reports_artifact_id", table_name="security_scan_reports")
    op.drop_table("security_scan_reports")
