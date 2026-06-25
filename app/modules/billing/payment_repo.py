from __future__ import annotations

from uuid import UUID
import logging
from uuid import UUID
from datetime import datetime, timezone


from sqlalchemy import or_, select, update, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import SQLAlchemyError

from app.modules.software_management.software.software import Software
from app.infrastructure.database.models.software import SoftwareModel, SoftwareVersionModel
from app.modules.software_management.software.exceptions import RepositoryUnavailableError, SoftwareNotFoundError, SoftwareDomainError
from app.modules.software_management.software.value_objects import SoftwareCard, OwnedSoftwareCard  
from app.modules.software_management.software.enums import SoftwareStatus, SoftwareVisibility
from app.infrastructure.database.models.payment import SoftwarePaymentModel, SoftwarePurchaseModel


# Set up logging
logger = logging.getLogger(__name__)


class BillingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_payment(self, payment: SoftwarePaymentModel) -> SoftwarePaymentModel:
        try:
            self.session.add(payment)
            await self.session.refresh(payment)
            return payment
        except SQLAlchemyError as e:
            logger.error(f"Error saving payment: {e}")
            await self.session.rollback()
            raise RepositoryUnavailableError("Failed to save payment due to database error.")
    
    
    async def save_purchase(self, purchase: SoftwarePurchaseModel) -> SoftwarePurchaseModel:
        try:
            self.session.add(purchase)
            await self.session.refresh(purchase)
            return purchase
        except SQLAlchemyError as e:
            logger.error(f"Error saving purchase: {e}")
            await self.session.rollback()
            raise RepositoryUnavailableError("Failed to save purchase due to database error.")
        
    async def get_payment_by_id(self, payment_id: UUID) -> SoftwarePaymentModel:
        try:
            result = await self.session.execute(
                select(SoftwarePaymentModel).where(SoftwarePaymentModel.id == str(payment_id))
            )
            payment = result.scalar_one_or_none()
            if not payment:
                raise SoftwareNotFoundError(f"Payment with ID {payment_id} not found.")
            return payment
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving payment by ID: {e}")
            raise RepositoryUnavailableError("Failed to retrieve payment due to database error.")
        
    async def get_purchase_by_id(self, purchase_id: UUID) -> SoftwarePurchaseModel:
        try:
            result = await self.session.execute(
                select(SoftwarePurchaseModel).where(SoftwarePurchaseModel.id == str(purchase_id))
            )
            purchase = result.scalar_one_or_none()
            if not purchase:
                raise SoftwareNotFoundError(f"Purchase with ID {purchase_id} not found.")
            return purchase
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving purchase by ID: {e}")
            raise RepositoryUnavailableError("Failed to retrieve purchase due to database error.")
        
    
    async def update_payment_status(self, payment_id: UUID, new_status: str) -> SoftwarePaymentModel:
        try:
            raise NotImplementedError()
        except:
            raise NotImplementedError()