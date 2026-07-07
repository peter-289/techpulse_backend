from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import UUID, uuid4

from app.modules.billing.checkout_service import CheckoutService
from app.modules.billing.domain.value_objects import Currency, Money
from app.modules.shared.enums import PaymentProvider, PaymentResourceType, PaymentStatus


class StubSoftwareService:
    def __init__(self, software: object) -> None:
        self._software = software
        self.calls: list[UUID] = []

    async def get(self, software_id: UUID) -> object:
        self.calls.append(software_id)
        return self._software


class StubPurchaseService:
    def __init__(self, has_purchase: bool) -> None:
        self._has_purchase = has_purchase
        self.calls: list[tuple[UUID, UUID]] = []

    async def has_purchase(self, *, software_id: UUID, buyer_id: UUID) -> bool:
        self.calls.append((software_id, buyer_id))
        return self._has_purchase


class StubAccessPolicy:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def ensure_can_purchase(self, *, software: object, buyer_id: UUID, has_purchase: bool) -> None:
        self.calls.append({"software": software, "buyer_id": buyer_id, "has_purchase": has_purchase})


class StubPaymentService:
    def __init__(self) -> None:
        self.commands: list[object] = []
        self.started: list[tuple[object, PaymentProvider]] = []

    async def create(self, cmd: object) -> object:
        self.commands.append(cmd)
        return SimpleNamespace(
            id=uuid4(),
            buyer_id=cmd.buyer_id,
            provider=cmd.provider,
            amount=cmd.amount,
            provider_details=SimpleNamespace(reference=""),
            status=PaymentStatus.PENDING,
            created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            completed_at=None,
        )


def test_create_checkout_orchestrates_the_flow() -> None:
    software_id = uuid4()
    buyer_id = uuid4()
    owner_id = uuid4()
    software = SimpleNamespace(
        id=software_id,
        owner_id=owner_id,
        price_cents=2500,
        currency="USD",
        is_owned_by=lambda actor_id: actor_id == owner_id,
        is_archived=lambda: False,
        is_deleted=lambda: False,
        is_public=lambda: True,
        requires_payment=lambda: True,
        is_active=lambda: True,
    )

    software_service = StubSoftwareService(software)
    purchase_service = StubPurchaseService(has_purchase=False)
    access_policy = StubAccessPolicy()
    payment_service = StubPaymentService()

    service = CheckoutService(
        software_service=software_service,
        payment_service=payment_service,
        purchase_service=purchase_service,
        access_policy=access_policy,
    )

    session = asyncio.run(
        service.create_checkout(
            software_id=software_id,
            buyer_id=buyer_id,
            provider=PaymentProvider.STRIPE,
        )
    )

    assert session.software_id == software_id
    assert session.buyer_id == buyer_id
    assert session.owner_id == owner_id
    assert session.amount == Money(amount_cents=2500, currency=Currency(code="USD"))
    assert session.provider == PaymentProvider.STRIPE
    assert session.status == PaymentStatus.PENDING
    assert software_service.calls == [software_id]
    assert purchase_service.calls == [(software_id, buyer_id)]
    assert access_policy.calls == [
        {"software": software, "buyer_id": buyer_id, "has_purchase": False}
    ]
    assert len(payment_service.commands) == 1
    assert payment_service.commands[0].buyer_id == buyer_id
    assert payment_service.commands[0].subject.resource_type == PaymentResourceType.SOFTWARE
    assert payment_service.commands[0].subject.resource_id == software_id
