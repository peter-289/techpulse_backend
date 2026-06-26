from __future__ import annotations


from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import UUID
from sqlalchemy import select, exists

from app.infrastructure.database.models.payment import SoftwarePurchaseModel
from app.modules.shared.enums import PurchaseStatus


class PurchaseRepository:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def has_purchase(self, software_id: UUID, buyer_id: UUID) -> bool:
          """Check if an active purchase exists for software and buyer."""
          stmt = select(
                 exists().where(
                           SoftwarePurchaseModel.software_id == str(software_id),
                           SoftwarePurchaseModel.buyer_id == str(buyer_id),
                           SoftwarePurchaseModel.status == PurchaseStatus.ACTIVE.value,
                        )
            )
    
          result = await self.db.scalar(stmt)
          return bool(result)