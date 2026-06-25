from __future__ import annotations


from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import UUID
from sqlalchemy import select, exists

from app.infrastructure.database.models.payment import SoftwarePurchaseModel
from app.modules.shared.enums import PurchaseStatus


class PurchaseRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    def create_purchase(self, purchase_data):
        # Logic to create a new purchase record in the database
        pass

    def get_purchase_by_id(self, purchase_id):
        # Logic to retrieve a purchase record by its ID
        pass

    def update_purchase(self, purchase_id, update_data):
        # Logic to update an existing purchase record
        pass

    def delete_purchase(self, purchase_id):
        # Logic to delete a purchase record from the database
        pass

    def list_purchases(self, filters=None):
        # Logic to list all purchases with optional filtering
        pass

    
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