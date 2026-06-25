from __future__ import annotations

import asyncio
import hashlib
import hmac
import shutil
import time
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO
from urllib.parse import quote
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.modules.software_management.software.software import Software
from app.modules.software_management.software.artifact import Artifact
from app.modules.software_management.software.version import Version
from app.modules.software_management.software.value_objects import SemVer
from app.modules.shared.enums import SoftwareVisibility, VersionStatus, ArtifactStatus
from app.modules.software_management.software.events import malware_scan_failed, malware_scan_success, malware_scan_requested
from app.modules.software_management.software.exceptions import (
    SoftwareAccessDeniedError,
    SoftwareDomainError,
    SoftwareNotFoundError,
)
from app.infrastructure.database.models.payment import SoftwarePaymentModel, SoftwarePurchaseModel
from app.modules.software_management.software_repo import SoftwareRepository
from app.infrastructure.external_apis.scanner_service.malware_scanner import MalwareScanner, get_malware_scanner
from techpulse_backend.app.modules.billing.payment_service import PaymentProvider, get_payment_provider
from app.infrastructure.database.unit_of_work import UnitOfWork


# Set up logger
logger = logging.getLogger(__name__)




class BillingService:
    def __init__(self, unit_of_work: UnitOfWork, payment_provider: PaymentProvider):
        self.uow = unit_of_work
        self.payment_provider = payment_provider

    async def create_checkout(
        self,
        *,
        software: Software,
        user_id: int,
    ) -> SoftwarePaymentModel:
        """Create payment checkout for software purchase. Caller must provide a software object and the user ID of the buyer. Returns a SoftwarePaymentModel representing the payment intent."""
        buyer_id = self.actor_uuid(user_id)

        # Check for existing pending payment
        async with self.uow.read_only():
            existing = await self.uow.billing_repo.get_payment_by_id(payment_id=uuid4())
        if existing:
            return existing

        now = datetime.now(timezone.utc)
        payment_id = str(uuid4())
        intent = self.payment_provider.create_intent(
            payment_id=payment_id,
            amount_cents=software.price_cents,
            currency=software.currency,
            description=f"Project purchase: {software.name}",
            buyer_id=str(buyer_id),
            owner_id=str(software.owner_id),
        )
        if existing:
            return existing

        payment = SoftwarePaymentModel(
            id=payment_id,
            software_id=str(software.id),
            buyer_id=str(buyer_id),
            owner_id=str(software.owner_id),
            amount_cents=software.price_cents,
            currency=software.currency,
            status=intent.status,
            provider=intent.provider,
            provider_reference=intent.provider_reference,
            created_at=now,
            updated_at=now,
        )
        async with self.uow:
            await self.uow.billing_repo.save_payment(payment)


    async def confirm_checkout(
        self,
        *,
        payment_id: UUID,
        user_id: int,
    ) -> SoftwarePaymentModel:
        """Confirm payment and create purchase record."""
        buyer_id = str(self.actor_uuid(user_id))

        payment = await self.uow.billing_repo.get_payment(str(payment_id))
        if payment is None or payment.buyer_id != buyer_id:
            raise SoftwareNotFoundError("Payment not found.")

        if payment.status == "completed":
            return payment

        if payment.status != "pending":
            raise SoftwareDomainError("Only pending payments can be confirmed.")

        intent = self.payment_provider.confirm_intent(
            provider_reference=payment.provider_reference or payment.id
        )

        if intent.status != "completed":
            payment.status = intent.status
            payment.updated_at = datetime.now(timezone.utc)
            raise NotImplementedError("Payment not completed. Current status: " + intent.status)
            

        now = datetime.now(timezone.utc)
        payment.status = "completed"
        payment.updated_at = now
        payment.completed_at = now

        purchase = SoftwarePurchaseModel(
            id=str(uuid4()),
            software_id=payment.software_id,
            buyer_id=payment.buyer_id,
            owner_id=payment.owner_id,
            payment_id=payment.id,
            amount_cents=payment.amount_cents,
            currency=payment.currency,
            purchased_at=now,
        )
        async with self.uow:
             await self.uow.billing_repo.save_purchase(purchase)