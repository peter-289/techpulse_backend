from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from sqlalchemy.sql.elements import ColumnElement


from app.infrastructure.database.models.audit_event import AuditEvent
from app.infrastructure.database.models.security_alert import SecurityAlert



class AuditRepository:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    # Add event to db
    async def add_event(self, event: AuditEvent) -> AuditEvent:
        """ Add audit events"""
        self.db.add(event)
        await self.db.flush()
        await self.db.refresh(event)
        return event
    
    # List events
    async def count_events(self, predicates: list[ColumnElement[bool]])-> int:
        """ Count audit events"""
        stmt = select(func.count(AuditEvent.id)).where(and_(*predicates))
        result = await self.db.execute(stmt)
        return result.scalar_one()
        
        
    async def get_alert(self, predicates: list[ColumnElement[bool]])->SecurityAlert:
        """ Get security alert"""
        stmt = select(SecurityAlert.id).where(and_(*predicates)).limit(1)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

  
    async def add_alert(self, alert: SecurityAlert) -> SecurityAlert:
        """ Add security alert."""
        self.db.add(alert)
        await self.db.flush()
        await self.db.refresh(alert)
        return alert