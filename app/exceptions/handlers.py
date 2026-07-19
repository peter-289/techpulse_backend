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
    PurchaseNotFoundError,
    PaymentDomainError,
    InvalidMoneyError,
    InvalidCurrencyError,
    DuplicatePaymentError,
    DuplicatePurchaseError,
    InvalidWebhookSignatureError,
    UnsupportedPaymentProviderError,
    InvalidGatewayConfigurationError,
    DuplicateGatewayRegistrationError,
    RepositoryUnavailableError,
    OwnerCannotPurchaseError,
    PaymentProviderGatewayError,
    PaymentGatewayUnavailableError,
    PaymentProviderTimeoutError,
    PaymentProviderAuthenticationError,
    PaymentProviderRequestError,
    RefundFailedError, 
    
)
from app.modules.billing.domain.exceptions import (
    DuplicatePendingPaymentError,
    InvalidPaymentStateTransitionError,
    PaymentNotFoundError,
    PaymentAccessDenied,
    InvalidProviderReference,
    WebhookProcessingError,
)
from app.modules.software_management.software.exceptions import (
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
)
from app.modules.software_management.category.domain.exceptions import (
    CategoryDomainError,
    CategoryNotFoundError,
    DuplicateCategoryError,
    CategoryInUseError,
    CategoryDeletedError,
    CategoryRepositoryUnavailableError,
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
    
    @app.exception_handler(PaymentDomainError)
    async def _payment_exception_handler(_request: Request, exc: PaymentDomainError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})
    
    @app.exception_handler(PaymentNotFoundError)
    async def _payment_not_found_handler(_request: Request, exc: PaymentNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})
    
    @app.exception_handler(DuplicatePendingPaymentError)
    async def _duplicate_pending_payment_handler(_request: Request, exc: DuplicatePendingPaymentError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})
    
    @app.exception_handler(InvalidPaymentStateTransitionError)
    async def _invalid_payment_transition_handler(_request: Request, exc: InvalidPaymentStateTransitionError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})
    
    @app.exception_handler(PurchaseNotFoundError)
    async def _purchase_error_handler(_request: Request, exc: PurchaseNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})
    
    @app.exception_handler(InvalidMoneyError)
    async def _invalid_money_handler(_request: Request, exc: InvalidMoneyError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(InvalidCurrencyError)
    async def _invalid_currency_handler(_request: Request, exc: InvalidCurrencyError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": str(exc)})

    @app.exception_handler(DuplicatePaymentError)
    async def _duplicate_payment_handler(_request: Request, exc: DuplicatePaymentError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(DuplicatePurchaseError)
    async def _duplicate_purchase_handler(_request: Request, exc: DuplicatePurchaseError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(InvalidWebhookSignatureError)
    async def _invalid_webhook_signature_handler(_request: Request, exc: InvalidWebhookSignatureError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": str(exc)})

    @app.exception_handler(UnsupportedPaymentProviderError)
    async def _unsupported_payment_provider_handler(_request: Request, exc: UnsupportedPaymentProviderError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(InvalidGatewayConfigurationError)
    async def _invalid_gateway_configuration_handler(_request: Request, exc: InvalidGatewayConfigurationError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": str(exc)})

    @app.exception_handler(DuplicateGatewayRegistrationError)
    async def _duplicate_gateway_registration_handler(_request: Request, exc: DuplicateGatewayRegistrationError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})

    @app.exception_handler(RepositoryUnavailableError)
    async def _repository_unavailable_handler(_request: Request, exc: RepositoryUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(OwnerCannotPurchaseError)
    async def _owner_cannot_purchase_handler(_request: Request, exc: OwnerCannotPurchaseError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(PaymentProviderGatewayError)
    async def _payment_provider_gateway_handler(_request: Request, exc: PaymentProviderGatewayError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(PaymentGatewayUnavailableError)
    async def _payment_gateway_unavailable_handler(_request: Request, exc: PaymentGatewayUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(PaymentProviderTimeoutError)
    async def _payment_provider_timeout_handler(_request: Request, exc: PaymentProviderTimeoutError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_504_GATEWAY_TIMEOUT, content={"detail": str(exc)})

    @app.exception_handler(PaymentProviderAuthenticationError)
    async def _payment_provider_authentication_handler(_request: Request, exc: PaymentProviderAuthenticationError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": str(exc)})

    @app.exception_handler(PaymentProviderRequestError)
    async def _payment_provider_request_handler(_request: Request, exc: PaymentProviderRequestError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})

    @app.exception_handler(RefundFailedError)
    async def _refund_failed_handler(_request: Request, exc: RefundFailedError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    @app.exception_handler(PaymentAccessDenied)
    async def _payment_access_denied_handler(_request: Request, exc: PaymentAccessDenied) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)})

    @app.exception_handler(InvalidProviderReference)
    async def _invalid_provider_reference_handler(_request: Request, exc: InvalidProviderReference) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    @app.exception_handler(WebhookProcessingError)
    async def _webhook_processing_error_handler(_request: Request, exc: WebhookProcessingError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

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

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled server error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )
