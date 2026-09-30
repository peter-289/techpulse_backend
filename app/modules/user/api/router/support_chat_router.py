from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.shared.dependencies import get_db
from app.modules.security.dependencies import CurrentUser, get_current_user
from app.modules.user.dependencies import get_support_ai
from app.modules.user.application.services.support_chat_service import SupportChatService
from app.modules.user.domain.ports.support_ai import SupportAI
from app.modules.user.schema.support_chat_schema import (
    SupportChatMessageRead,
    SupportChatRequest,
    SupportChatResponse,
)

router = APIRouter(prefix="/api/v1/support-chat", tags=["Support Chat"])


def get_unit_of_work(session: AsyncSession = Depends(get_db)) -> UnitOfWork:
    """Provide a UnitOfWork for the request scope.

    The composition root for this part of the context. It is the only place that
    names the concrete transaction adapter.
    """
    return UnitOfWork(session=session)


def get_service(
    uow: UnitOfWork = Depends(get_unit_of_work),
    support_ai: SupportAI = Depends(get_support_ai),
) -> SupportChatService:
    return SupportChatService(uow=uow, support_ai=support_ai)


@router.post("/messages", response_model=SupportChatResponse, status_code=201)
async def send_message(
    payload: SupportChatRequest,
    service: SupportChatService = Depends(get_service),
    current_user: CurrentUser = Depends(get_current_user),
):
    message = await service.ask(user_id=current_user.user_id, message=payload.message)
    return {"message_id": message.id, "assistant_reply": message.assistant_message}


@router.get("/messages", response_model=list[SupportChatMessageRead], status_code=200)
async def list_messages(
    limit: int = Query(25, ge=1, le=100),
    service: SupportChatService = Depends(get_service),
    current_user: CurrentUser = Depends(get_current_user),
):
    return await service.list_messages(user_id=current_user.user_id, limit=limit)
