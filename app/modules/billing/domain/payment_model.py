from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4
from datetime import datetime, timezone

from app.modules.shared.enums import PaymentProvider, PaymentStatus
from app.modules.billing.domain.value_objects import PaymentSubject, Money, PaymentProviderDetails
from app.exceptions.exceptions import PaymentDomainError



@dataclass(slots=True)
class Payment:

    # Identity
    id: UUID

    # References
    buyer_id: UUID
    subject: PaymentSubject

    # Financial data
    amount: Money

    # Provider
    provider: PaymentProvider
    provider_details: PaymentProviderDetails | None = None

    failure_reason: str | None = None
    refund_reference: str | None = None

    # Lifecycle
    status: PaymentStatus


    # Timestamps
    created_at: datetime 
    updated_at: datetime
    
    completed_at: datetime | None = None
    refunded_at: datetime  | None = None
    canceled_at: datetime  | None = None

    lock_version: int = 0

    # Factory
    @classmethod
    def create(
        cls,
        *,
        buyer_id: UUID,
        subject: PaymentSubject,
        amount: Money,
        provider: PaymentProvider,
        provider_details: PaymentProviderDetails,
        ) -> "Payment":

        now = datetime.now(timezone.utc)

        return cls(
            id=uuid4(),
            buyer_id=buyer_id,
            subject=subject,
            amount=amount,
            provider=provider,
            provider_details=provider_details,
            failure_reason=None,
            refund_reference=None,
            status=PaymentStatus.PENDING,
            created_at=now,
            updated_at=now,
            completed_at=None,
            refunded_at=None,
            canceled_at=None,

            lock_version=0,
        )


    # Commands
    def start_processing(self):
          """Initialize payment processing."""
          self._ensure_status(PaymentStatus.PENDING, "Start payment processing...")
          self.status = PaymentStatus.PROCESSING
          self._touch()

    def mark_succeeded(self, provider_reference: str | None = None) -> None:
        """Transition from PROCESSING to COMPLETED."""
        self._ensure_status(PaymentStatus.PROCESSING, "Mark payment as successful.")
        self.status = PaymentStatus.COMPLETED
        self.completed_at = self._utc_now()

        if provider_reference:
            self.provider_details = self.provider_details or PaymentProviderDetails()
            self.provider_details.reference = provider_reference
        self._touch()
    
    def mark_failed(self, reason: str) -> None:
        """Transition from PROCESSING to FAILED."""
        self._ensure_status(PaymentStatus.PROCESSING, "Mark payment as failed...")
        self.status = PaymentStatus.FAILED
        self.failure_reason = reason
        self._touch()

    def cancel(self, reason: str | None = None) -> None:
        """Transition from PENDING to CANCELED."""
        self._ensure_status(PaymentStatus.PENDING, PaymentStatus.PROCESSING, action="Cancel payment.")
        self.status = PaymentStatus.CANCELLED
        self.canceled_at = self._utc_now()
        if reason:
            self.failure_reason = reason
        self._touch()

    def refund(self, reference: str, amount: Money | None = None) -> None:
        """Transition from COMPLETED to REFUNDED."""
        if not self.can_be_refunded:
            raise PaymentDomainError("Payment can not be refunded.")
        
        if amount and amount > self.amount:
            raise PaymentDomainError(
                f"Refund amount {amount} exceeds payment amount {self.amount}."
            )
        self.status = PaymentStatus.REFUNDED
        self.refund_reference = reference
        self.refunded_at = self._utc_now()
        self._touch()



    # ─── Helpers ───
    def _ensure_status(
      self,
      *expected: PaymentStatus,
      action: str,
    ) -> None:
       """Guard against invalid state transitions."""
       if self.status in expected:
          return

       expected_values = ", ".join(s.value for s in expected)
       raise PaymentDomainError(
           f"Cannot {action} from {self.status.value}. "
           f"Expected one of: {expected_values}."
        )
    
    def _touch(self) -> None:
        """Update timestamp and increment lock version."""
        self.updated_at = self._utc_now()
        self.lock_version += 1
    
    def _utc_now():
        return datetime.now(timezone.utc)
    
    
    
    # === Queries ===
    @property
    def is_successful(self) -> bool:
        return self.status == PaymentStatus.COMPLETED

    @property
    def is_pending(self) -> bool:
        return self.status == PaymentStatus.PENDING

    @property
    def is_processing(self) -> bool:
        return self.status == PaymentStatus.PROCESSING

    @property
    def is_failed(self) -> bool:
        return self.status == PaymentStatus.FAILED

    @property
    def is_refunded(self) -> bool:
        return self.status == PaymentStatus.REFUNDED

    @property
    def is_canceled(self) -> bool:
        return self.status == PaymentStatus.CANCELED

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            PaymentStatus.COMPLETED,
            PaymentStatus.FAILED,
            PaymentStatus.REFUNDED,
            PaymentStatus.CANCELED,
        }

    @property
    def can_be_refunded(self) -> bool:
        return self.status == PaymentStatus.COMPLETED and self.refunded_at is None

    @property
    def can_be_canceled(self) -> bool:
        return self.status in {PaymentStatus.PENDING, PaymentStatus.PROCESSING}

    @property
    def can_be_retried(self) -> bool:
        return self.status in {PaymentStatus.FAILED, PaymentStatus.CANCELED}