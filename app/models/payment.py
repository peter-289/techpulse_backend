from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.db_setup import Base


class SoftwarePaymentModel(Base):
    __tablename__ = "sms_payments"
    __table_args__ = (
        Index("ix_sms_payments_buyer_id", "buyer_id"),
        Index("ix_sms_payments_software_id", "software_id"),
        Index("ix_sms_payments_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    software_id: Mapped[str] = mapped_column(ForeignKey("sms_softwares.id", ondelete="CASCADE"), nullable=False)
    buyer_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    provider: Mapped[str] = mapped_column(String(40), nullable=False, default="manual")
    provider_reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SoftwarePurchaseModel(Base):
    __tablename__ = "sms_purchases"
    __table_args__ = (
        UniqueConstraint("software_id", "buyer_id", name="uq_sms_purchases_software_buyer"),
        Index("ix_sms_purchases_buyer_id", "buyer_id"),
        Index("ix_sms_purchases_software_id", "software_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    software_id: Mapped[str] = mapped_column(ForeignKey("sms_softwares.id", ondelete="CASCADE"), nullable=False)
    buyer_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payment_id: Mapped[str] = mapped_column(ForeignKey("sms_payments.id", ondelete="CASCADE"), nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    purchased_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
