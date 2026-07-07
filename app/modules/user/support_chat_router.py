from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession



from app.modules.shared.dependencies import get_current_user, CurrentUser
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.shared.dependencies import get_db
from app.modules.user.support_chat_schema import SupportChatMessageRead, SupportChatRequest, SupportChatResponse
from app.modules.user.support_chat_service import SupportChatService

router = APIRouter(prefix="/api/v1/support-chat", tags=["Support Chat"])


def get_service(db: AsyncSession = Depends(get_db)) -> SupportChatService:
    return SupportChatService(UnitOfWork(session=db))


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

