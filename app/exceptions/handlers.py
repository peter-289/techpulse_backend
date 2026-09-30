from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
import logging


from app.exceptions.exceptions import (
    ConflictError,
    DomainError,
    ExternalServiceError,
    NotFoundError,
    PermissionError,
    ValidationError,
    UnauthorizedError,
    TooManyRequestsError,
    InvalidMoneyError,
    InvalidCurrencyError,
    RepositoryUnavailableError,
)

from app.modules.software_management.domain.exceptions import (
    SoftwareDomainError,
    SoftwareNotFoundError,
    SoftwareAccessDeniedError,
    OwnerCannotPurchaseError as SoftwareOwnerCannotPurchaseError,
    DuplicatePurchaseError as SoftwareDuplicatePurchaseError,
    SoftwareArchivedError,
    SoftwareDeletedError,
    SoftwareNotPublishedError,
    VersionUnavailableError,
    DownloadDeniedError,
    InvalidStateTransitionError,
    InvalidSemVerError,
    ArtifactIntegrityError,
    MalwareScanPendingError,
    SoftwareValidationError,
    RepositoryUnavailableError as SoftwareRepositoryUnavailableError,
        CategoryDomainError,
        CategoryNotFoundError,
        DuplicateCategoryError,
        CategoryInUseError,
        CategoryDeletedError,
        CategoryRepositoryUnavailableError,
)
from app.modules.software_management.domain.ports.storage import (
    StorageError,
    StorageUnavailableError,
    StorageWriteError,
    StorageReadError,
    StorageFileNotFoundError,
    StorageSecurityError,
)
from app.modules.user.domain.exceptions import (
    UserDomainError,
    ChatMessageDomainError,
    ChatMessageTooShortError,
    ChatMessageRepositoryUnavailableError,
)
from app.modules.user.domain.ports.support_ai import SupportAIUnavailableError
from app.modules.resource.domain.exceptions import (
    ResourceDomainError,
    ResourceNotFoundError,
    DuplicateResourceSlugError,
    InvalidResourceTypeError,
    ResourceRepositoryUnavailableError,
)
from app.modules.software_management.domain.ports.artifact_stager import (
    StagingError,
    StagingTooLargeError,
)

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NotFoundError)
    async def _not_found_handler(_request: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    @app.exception_handler(ConflictError)
    async def _conflict_handler(_request: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(UnauthorizedError)
    async def _unauthorized_handler(_request: Request, exc: UnauthorizedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": str(exc)})

    @app.exception_handler(ValidationError)
    async def _validation_handler(_request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(PermissionError)
    async def _permission_handler(_request: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(ExternalServiceError)
    async def _external_service_handler(_request: Request, exc: ExternalServiceError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(DomainError)
    async def _domain_handler(_request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(TooManyRequestsError)
    async def _too_many_requests_handler(_request: Request, exc: TooManyRequestsError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"detail": str(exc)})
    
    @app.exception_handler(InvalidMoneyError)
    async def _invalid_money_handler(_request: Request, exc: InvalidMoneyError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(InvalidCurrencyError)
    async def _invalid_currency_handler(_request: Request, exc: InvalidCurrencyError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(RepositoryUnavailableError)
    async def _repository_unavailable_handler(_request: Request, exc: RepositoryUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(SoftwareDomainError)
    async def _software_domain_error_handler(_request: Request, exc: SoftwareDomainError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(SoftwareNotFoundError)
    async def _software_not_found_handler(_request: Request, exc: SoftwareNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    @app.exception_handler(SoftwareAccessDeniedError)
    async def _software_access_denied_handler(_request: Request, exc: SoftwareAccessDeniedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(SoftwareOwnerCannotPurchaseError)
    async def _software_owner_cannot_purchase_handler(_request: Request, exc: SoftwareOwnerCannotPurchaseError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(SoftwareDuplicatePurchaseError)
    async def _software_duplicate_purchase_handler(_request: Request, exc: SoftwareDuplicatePurchaseError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(SoftwareArchivedError)
    async def _software_archived_handler(_request: Request, exc: SoftwareArchivedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(SoftwareDeletedError)
    async def _software_deleted_handler(_request: Request, exc: SoftwareDeletedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_410_GONE, content={"detail": str(exc)})

    @app.exception_handler(SoftwareNotPublishedError)
    async def _software_not_published_handler(_request: Request, exc: SoftwareNotPublishedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(VersionUnavailableError)
    async def _version_unavailable_handler(_request: Request, exc: VersionUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(DownloadDeniedError)
    async def _download_denied_handler(_request: Request, exc: DownloadDeniedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(InvalidStateTransitionError)
    async def _invalid_state_transition_handler(_request: Request, exc: InvalidStateTransitionError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(InvalidSemVerError)
    async def _invalid_semver_handler(_request: Request, exc: InvalidSemVerError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(ArtifactIntegrityError)
    async def _artifact_integrity_handler(_request: Request, exc: ArtifactIntegrityError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(MalwareScanPendingError)
    async def _malware_scan_pending_handler(_request: Request, exc: MalwareScanPendingError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(SoftwareValidationError)
    async def _software_validation_handler(_request: Request, exc: SoftwareValidationError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(SoftwareRepositoryUnavailableError)
    async def _software_repository_unavailable_handler(_request: Request, exc: SoftwareRepositoryUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(CategoryDomainError)
    async def _category_domain_error_handler(_request: Request, exc: CategoryDomainError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(CategoryNotFoundError)
    async def _category_not_found_handler(_request: Request, exc: CategoryNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    @app.exception_handler(DuplicateCategoryError)
    async def _duplicate_category_handler(_request: Request, exc: DuplicateCategoryError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(CategoryInUseError)
    async def _category_in_use_handler(_request: Request, exc: CategoryInUseError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(CategoryDeletedError)
    async def _category_deleted_handler(_request: Request, exc: CategoryDeletedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(CategoryRepositoryUnavailableError)
    async def _category_repository_unavailable_handler(_request: Request, exc: CategoryRepositoryUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(StorageFileNotFoundError)
    async def _storage_file_not_found_handler(_request: Request, exc: StorageFileNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    @app.exception_handler(StorageSecurityError)
    async def _storage_security_handler(_request: Request, exc: StorageSecurityError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(StorageReadError)
    async def _storage_read_error_handler(_request: Request, exc: StorageReadError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)})

    @app.exception_handler(StorageUnavailableError)
    async def _storage_unavailable_handler(_request: Request, exc: StorageUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(StorageWriteError)
    async def _storage_write_error_handler(_request: Request, exc: StorageWriteError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)})

    @app.exception_handler(StorageError)
    async def _storage_error_handler(_request: Request, exc: StorageError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)})

    # Staging failures get the same codes the equivalent domain errors produced
    # before the staging port existed, so an oversized or unstageable upload
    # keeps returning the status the API contract already promised.
    @app.exception_handler(StagingTooLargeError)
    async def _staging_too_large_handler(_request: Request, exc: StagingTooLargeError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(StagingError)
    async def _staging_error_handler(_request: Request, exc: StagingError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)})

    # Resource failures keep the codes the shared-kernel errors produced before
    # this context had a domain model, so no route changed behaviour.
    @app.exception_handler(ResourceDomainError)
    async def _resource_domain_error_handler(_request: Request, exc: ResourceDomainError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(ResourceNotFoundError)
    async def _resource_not_found_handler(_request: Request, exc: ResourceNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    @app.exception_handler(DuplicateResourceSlugError)
    async def _duplicate_resource_slug_handler(_request: Request, exc: DuplicateResourceSlugError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(InvalidResourceTypeError)
    async def _invalid_resource_type_handler(_request: Request, exc: InvalidResourceTypeError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    # 500, not 503: a driver error used to escape as an unhandled exception and
    # that is what the contract says. 503 would be more accurate but is an
    # observable change, so it waits for the phase that may alter the contract.
    @app.exception_handler(ResourceRepositoryUnavailableError)
    async def _resource_repository_unavailable_handler(_request: Request, exc: ResourceRepositoryUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)})

    # Support chat: 422 is the code the shared-kernel ValidationError produced
    # for a too-short question. ChatMessageDomainError is its base and maps to
    # 400, matching every other context's domain-error base.
    @app.exception_handler(UserDomainError)
    async def _user_domain_error_handler(_request: Request, exc: UserDomainError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(ChatMessageDomainError)
    async def _chat_message_domain_error_handler(_request: Request, exc: ChatMessageDomainError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(ChatMessageTooShortError)
    async def _chat_message_too_short_handler(_request: Request, exc: ChatMessageTooShortError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(ChatMessageRepositoryUnavailableError)
    async def _chat_message_repository_unavailable_handler(_request: Request, exc: ChatMessageRepositoryUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)})

    # 503 for parity with the ExternalServiceError this replaced. Unreachable in
    # practice: the service catches it and substitutes a canned reply, exactly
    # as it caught the ExternalServiceError before, so the client still gets 201.
    @app.exception_handler(SupportAIUnavailableError)
    async def _support_ai_unavailable_handler(_request: Request, exc: SupportAIUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled server error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )
