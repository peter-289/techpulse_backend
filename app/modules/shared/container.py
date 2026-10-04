from dataclasses import dataclass

from app.core.config import settings
from app.infrastructure.storage.local_storage import (
    DownloadUrlSignerSettings,
    HmacDownloadUrlSigner,
    LocalStorage,
    StorageSettings,
)




# Mail management configuration
@dataclass(frozen=True)
class MailConfig:
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_STARTTLS: bool
    MAIL_SSL_TLS: bool
    USE_CREDENTIALS: bool
    VALIDATE_CERTS: bool


# Mail configuration
mail_config = MailConfig(
    MAIL_USERNAME=settings.SMTP_USERNAME,
    MAIL_PASSWORD=settings.SMTP_PASSWORD,
    MAIL_FROM=settings.EMAIL_FROM,
    MAIL_PORT=settings.SMTP_PORT,
    MAIL_SERVER=settings.SMTP_HOST,
    MAIL_STARTTLS=settings.SMTP_USE_TLS,
    MAIL_SSL_TLS=settings.SMTP_USE_SSL,
    USE_CREDENTIALS=bool(settings.SMTP_USERNAME and settings.SMTP_PASSWORD),
    VALIDATE_CERTS=settings.SMTP_VALIDATE_CERTS,
)

# StorageSettings and DownloadUrlSignerSettings live beside the adapter they
# configure, in app.infrastructure.storage.local_storage, so the adapter's own
# annotations resolve without importing the composition root.
storage_settings = StorageSettings(
    backend_url=settings.BACKEND_URL,
    storage_root=settings.UPLOAD_ROOT,
    signing_secret=settings.SECRET_KEY,
)
signer_settings = DownloadUrlSignerSettings(
    backend_url=settings.BACKEND_URL,
    signing_secret=settings.SECRET_KEY,
    default_expiry_seconds=settings.URL_EXPIRY_MAX_SECONDS,
)


storage = LocalStorage(settings=storage_settings)
signer = HmacDownloadUrlSigner(settings=signer_settings)
