from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.modules.billing.domain.payment_model import Payment
from app.modules.billing.domain.value_objects import (
    Currency,
    Money,
    PaymentProviderDetails,
    PaymentSubject,
)
from app.modules.billing.payment_exceptions import (
    InvalidPaymentStateTransitionError,
    PaymentNotFoundError,
)
from app.modules.billing.payment_service import PaymentService
from app.modules.shared.enums import (
    PaymentProvider,
    PaymentResourceType,
    PaymentStatus,
)


class FakePaymentRepository:
    """In-memory repository stub for PaymentService unit tests."""

    def __init__(self) -> None:
        self._store: dict[str, Payment] = {}
        self.saved: list[Payment] = []

    async def get(self, payment_id: object) -> Payment | None:
        return self._store.get(str(payment_id))

    async def save(self, payment: Payment) -> Payment:
        self._store[str(payment.id)] = payment
        self.saved.append(payment)
        return payment


class FakeUnitOfWork:
    def __init__(self, repository: FakePaymentRepository) -> None:
        self.payment_repository = repository
        self.committed = False

    async def __aenter__(self) -> "FakeUnitOfWork":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        self.committed = True
        return False


def _make_payment(
    payment_id: object,
    *,
    status: PaymentStatus = PaymentStatus.PENDING,
    reference: str = "",
) -> Payment:
    return Payment(
        id=payment_id,
        buyer_id=uuid4(),
        subject=PaymentSubject(
            resource_type=PaymentResourceType.SOFTWARE,
            resource_id=uuid4(),
        ),
        amount=Money(amount_cents=2500, currency=Currency(code="USD")),
        provider=PaymentProvider.STRIPE,
        provider_details=PaymentProviderDetails(reference=reference),
        status=status,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def _service_with(payment: Payment | None) -> tuple[PaymentService, FakePaymentRepository]:
    repository = FakePaymentRepository()
    if payment is not None:
        repository._store[str(payment.id)] = payment
    return PaymentService(FakeUnitOfWork(repository)), repository


def test_attach_provider_reference_persists_reference() -> None:
    payment_id = uuid4()
    service, repository = _service_with(_make_payment(payment_id))

    updated = asyncio.run(
        service.attach_provider_reference(
            payment_id=payment_id, provider_reference="ref_abc"
        )
    )

    assert updated.provider_details is not None
    assert updated.provider_details.reference == "ref_abc"
    assert repository.saved[-1].provider_details.reference == "ref_abc"
    # attach_provider_reference transitions PENDING -> PROCESSING.
    assert updated.status == PaymentStatus.PROCESSING
    assert updated.lock_version == 1


def test_attach_provider_reference_missing_payment_raises() -> None:
    service, _ = _service_with(None)

    try:
        asyncio.run(
            service.attach_provider_reference(
                payment_id=uuid4(), provider_reference="ref_abc"
            )
        )
    except PaymentNotFoundError:
        return
    raise AssertionError("Expected PaymentNotFoundError")


def test_attach_provider_reference_non_pending_rejected() -> None:
    payment_id = uuid4()
    service, _ = _service_with(
        _make_payment(payment_id, status=PaymentStatus.COMPLETED)
    )

    try:
        asyncio.run(
            service.attach_provider_reference(
                payment_id=payment_id, provider_reference="ref_abc"
            )
        )
    except InvalidPaymentStateTransitionError:
        return
    raise AssertionError("Expected InvalidPaymentStateTransitionError")


def test_attach_provider_reference_empty_reference_rejected() -> None:
    payment_id = uuid4()
    service, _ = _service_with(_make_payment(payment_id))

    try:
        asyncio.run(
            service.attach_provider_reference(
                payment_id=payment_id, provider_reference=""
            )
        )
    except InvalidPaymentStateTransitionError:
        return
    raise AssertionError("Expected InvalidPaymentStateTransitionError")
