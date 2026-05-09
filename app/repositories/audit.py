from sqlalchemy.orm import Session
from sqlalchemy import select, or_, func, and_
from sqlalchemy.sql.elements import ColumnElement
from typing import Optional
from datetime import datetime

from app.models.audit_event import AuditEvent
from app.models.security_alert import SecurityAlert



class AuditRepository:
    def __init__(self, db: Session):
        self.db = db
    
    # Add event to db
    def add_event(self, event: AuditEvent) -> AuditEvent:
        self.db.add(event)
        self.db.flush()
        self.db.refresh(event)
        return event
    
    # List events
    def count_events(self, predicates: list[ColumnElement[bool]])-> int:
        """ Count audit events"""
        stmt = select(func.count(AuditEvent.id)).where(and_(*predicates))
        return self.db.execute(stmt).scalar_one()
        
    def get_alert(self, predicates: list[ColumnElement[bool]])->SecurityAlert:
        """ Get security alert"""
        stmt = select(SecurityAlert.id).where(and_(*predicates)).limit(1)
        return self.db.execute(stmt).scalar_one_or_none()
  
    def add_alert(self, alert: SecurityAlert) -> SecurityAlert:
        """ Add security alert."""
        self.db.add(alert)
        self.db.flush()
        self.db.refresh(alert)
        return alert