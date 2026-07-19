"""SQLAlchemy async persistence adapter for purchases.

Infrastructure-only. Translates between the ``Purchase`` aggregate and the
``SoftwarePurchaseModel`` persistence model. Never commits, rolls back, or
begins transactions; the Unit of Work owns the transaction lifecycle.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import exists, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions.exceptions import RepositoryUnavailableError
from app.infrastructure.database.models.payment import SoftwarePurchaseModel
from app.infrastructure.database.models.software import SoftwareModel, SoftwareVersionModel
from app.modules.billing.domain.purchase import Purchase
from app.modules.billing.domain.value_objects import Currency, Money, PurchaseHistoryCard
from app.modules.billing.domain.repositories.purchase_repository import (
    PurchaseRepositoryProtocol,
)
from app.modules.shared.enums import PurchaseStatus, SoftwareVisibility, VersionStatus
from app.modules.software_management.software.value_objects import OwnedSoftwareCard

logger = logging.getLogger(__name__)


class PurchaseRepository(PurchaseRepositoryProtocol):
    """SQLAlchemy async implementation of the purchase repository."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def find_by_payment(self, payment_id: UUID) -> Purchase | None:
        try:
            stmt = select(SoftwarePurchaseModel).where(
                SoftwarePurchaseModel.payment_id == str(payment_id)
            )
            model = await self.session.scalar(stmt)
            if model is None:
                return None
            return self._purchase_to_entity(model)
        except SQLAlchemyError as exc:
            logger.exception("Failed to fetch purchase by payment_id=%s", payment_id)
            raise RepositoryUnavailableError("Failed to retrieve purchase for payment.") from exc

    async def has_purchase(self, software_id: UUID, buyer_id: UUID) -> bool:
        stmt = select(
            exists().where(
                SoftwarePurchaseModel.software_id == str(software_id),
                SoftwarePurchaseModel.buyer_id == str(buyer_id),
                SoftwarePurchaseModel.status == PurchaseStatus.ACTIVE.value,
            )
        )
        result = await self.session.scalar(stmt)
        return bool(result)

    async def save(self, purchase: Purchase) -> None:
        model = SoftwarePurchaseModel(
            id=str(purchase.id),
            software_id=str(purchase.software_id),
            buyer_id=str(purchase.buyer_id),
            payment_id=str(purchase.payment_id),
            amount_cents=purchase.amount.amount_cents,
            currency=purchase.amount.currency.code,
            status=purchase.status.value,
            purchased_at=purchase.purchased_at,
            updated_at=purchase.updated_at,
            revoked_at=purchase.revoked_at,
            refunded_at=purchase.refunded_at,
            lock_version=purchase.lock_version,
        )
        try:
            await self.session.merge(model)
            await self.session.flush()
        except SQLAlchemyError as exc:
            raise RepositoryUnavailableError("Failed to stage purchase") from exc

    async def get(self, purchase_id: UUID) -> Purchase | None:
        try:
            stmt = select(SoftwarePurchaseModel).where(SoftwarePurchaseModel.id == str(purchase_id))
            model = await self.session.scalar(stmt)
            if model is None:
                return None
            return self._purchase_to_entity(model)
        except SQLAlchemyError as exc:
            logger.exception("Failed to fetch purchase %s", purchase_id)
            raise RepositoryUnavailableError("Failed to retrieve purchase.") from exc

    async def get_purchase(self, *, software_id: UUID, buyer_id: UUID) -> Purchase | None:
        try:
            stmt = select(SoftwarePurchaseModel).where(
                (SoftwarePurchaseModel.software_id == str(software_id)),
                (SoftwarePurchaseModel.buyer_id == str(buyer_id)),
            )
            result = await self.session.scalar(stmt)
            if result is None:
                return None
            return self._purchase_to_entity(result)
        except SQLAlchemyError as exc:
            logger.exception(
                "Failed to fetch purchase for software_id=%s buyer_id=%s", software_id, buyer_id
            )
            raise RepositoryUnavailableError(
                "Failed to retrieve purchase for buyer and software."
            ) from exc

    async def list_history(
        self, buyer_id: UUID, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[PurchaseHistoryCard], int]:
        try:
            buyer_key = str(buyer_id)
            where = SoftwarePurchaseModel.buyer_id == buyer_key
            count_stmt = select(func.count()).select_from(SoftwarePurchaseModel).where(where)
            total_count = await self.session.scalar(count_stmt) or 0

            stmt = (
                select(
                    SoftwarePurchaseModel.id.label("purchase_id"),
                    SoftwarePurchaseModel.software_id.label("software_id"),
                    SoftwareModel.name.label("software_name"),
                    SoftwarePurchaseModel.amount_cents.label("amount_cents"),
                    SoftwarePurchaseModel.currency.label("currency"),
                    SoftwarePurchaseModel.status.label("purchase_status"),
                    SoftwarePurchaseModel.purchased_at.label("purchased_at"),
                    SoftwarePurchaseModel.refunded_at.label("refunded_at"),
                    SoftwarePurchaseModel.revoked_at.label("revoked_at"),
                    func.coalesce(
                        SoftwarePurchaseModel.refunded_at,
                        SoftwarePurchaseModel.revoked_at,
                        SoftwarePurchaseModel.purchased_at,
                    ).label("last_activity_at"),
                )
                .join(SoftwareModel, SoftwarePurchaseModel.software_id == SoftwareModel.id)
                .where(where)
                .order_by(
                    SoftwarePurchaseModel.purchased_at.desc(),
                    SoftwarePurchaseModel.id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
            result = await self.session.execute(stmt)
            rows = result.mappings().all()
            items = [self._purchase_history_from_row(row) for row in rows]
            return items, int(total_count)
        except SQLAlchemyError as exc:
            logger.exception("Failed to list purchase history for buyer %s", buyer_id)
            raise RepositoryUnavailableError(
                f"Failed to list purchase history for buyer: {buyer_id}"
            ) from exc

    async def list_owned(
        self, buyer_id: UUID, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[OwnedSoftwareCard], int]:
        try:
            buyer_key = str(buyer_id)
            where = SoftwarePurchaseModel.buyer_id == buyer_key
            count_stmt = select(func.count()).select_from(SoftwarePurchaseModel).where(where)
            total_count = await self.session.scalar(count_stmt) or 0

            latest_version_sq = (
                select(SoftwareVersionModel.version)
                .where(
                    SoftwareVersionModel.software_id == SoftwareModel.id,
                    SoftwareVersionModel.status == VersionStatus.PUBLISHED.value,
                )
                .order_by(
                    SoftwareVersionModel.published_at.desc().nullslast(),
                    SoftwareVersionModel.created_at.desc(),
                    SoftwareVersionModel.id.desc(),
                )
                .limit(1)
                .scalar_subquery()
            )

            stmt = (
                select(
                    SoftwarePurchaseModel.id.label("purchase_id"),
                    SoftwarePurchaseModel.software_id.label("software_id"),
                    SoftwareModel.name.label("software_name"),
                    SoftwareModel.description.label("software_description"),
                    SoftwareModel.visibility.label("software_visibility"),
                    SoftwareModel.price_cents.label("software_price_cents"),
                    SoftwareModel.currency.label("software_currency"),
                    latest_version_sq.label("latest_published_version"),
                    SoftwarePurchaseModel.status.label("purchase_status"),
                    SoftwarePurchaseModel.purchased_at.label("purchased_at"),
                )
                .join(SoftwareModel, SoftwarePurchaseModel.software_id == SoftwareModel.id)
                .where(where)
                .order_by(
                    SoftwarePurchaseModel.purchased_at.desc(),
                    SoftwarePurchaseModel.id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )
            result = await self.session.execute(stmt)
            rows = result.mappings().all()
            items = [self._owned_card_from_row(row) for row in rows]
            return items, int(total_count)
        except SQLAlchemyError as exc:
            logger.exception("Failed to list owned software purchases for buyer %s", buyer_id)
            raise RepositoryUnavailableError(
                f"Failed to list owned software purchases for buyer: {buyer_id}"
            ) from exc

    def _purchase_to_entity(self, model: SoftwarePurchaseModel) -> Purchase:
        return Purchase(
            id=UUID(model.id),
            buyer_id=UUID(model.buyer_id),
            software_id=UUID(model.software_id),
            payment_id=UUID(model.payment_id),
            amount=Money(amount_cents=model.amount_cents, currency=Currency(model.currency)),
            status=PurchaseStatus(model.status),
            purchased_at=model.purchased_at,
            updated_at=model.updated_at,
            revoked_at=model.revoked_at,
            refunded_at=model.refunded_at,
            lock_version=model.lock_version,
        )

    def _owned_card_from_row(self, row: Any) -> OwnedSoftwareCard:
        return OwnedSoftwareCard(
            id=UUID(str(row["purchase_id"])),
            purchase_id=UUID(str(row["purchase_id"])),
            software_id=UUID(str(row["software_id"])),
            name=row["software_name"],
            description=row["software_description"],
            visibility=SoftwareVisibility(row["software_visibility"]),
            price_cents=row["software_price_cents"],
            currency=row["software_currency"],
            latest_version=row["latest_published_version"],
            purchase_status=PurchaseStatus(row["purchase_status"]),
            purchased_at=row["purchased_at"],
        )

    def _purchase_history_from_row(self, row: Any) -> PurchaseHistoryCard:
        return PurchaseHistoryCard(
            purchase_id=UUID(str(row["purchase_id"])),
            software_id=UUID(str(row["software_id"])),
            software_name=row["software_name"],
            amount=Money(amount_cents=row["amount_cents"], currency=Currency(row["currency"])),
            status=PurchaseStatus(row["purchase_status"]),
            purchased_at=row["purchased_at"],
            refunded_at=row["refunded_at"],
            revoked_at=row["revoked_at"],
            last_activity_at=row["last_activity_at"],
        )


__all__ = ["PurchaseRepository"]
