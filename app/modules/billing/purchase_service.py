from __future__ import annotations
from uuid import UUID

from app.infrastructure.database.unit_of_work import UnitOfWork




class PurchaseService:
    def __init__(self, unit_of_work: UnitOfWork):
        self.uow = unit_of_work
        
    
    async def has_purchase(self, software_id: UUID, buyer_id: UUID) -> bool:
        """Check if an active purchase exists for software and buyer."""
        async with self.uow.read_only():
            return await self.uow.purchase_repository.has_purchase(software_id, buyer_id)
    
    async def grant_purchase(self, ):
        pass
