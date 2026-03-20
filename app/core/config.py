from pathlib import Path
from urllib.parse import urlparse

from dataclasses import dataclass
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = Path(__file__).resolve().parents[2]

def _normalize_smtp_host(value: str) -> str:
    host = (value or "").strip()
    if not host:
        return host
    parsed = urlparse(host)
    if parsed.scheme:
        return parsed.hostname or host
    return host


def _resolve_path(value: str, fallback: str) -> str:
    raw = (value or "").strip() or fallback
    path = Path(raw)
    if not path.is_absolute():
        path = (BACKEND_ROOT / path).resolve()
    return str(path)


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core
    DATABASE_URL: str = "sqlite:///tech_pulse.db"
    SECRET_KEY: str = "dev_secret_key_change_me_1234567890abcdef"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # Logging/Audit
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = "logs"
    LOG_FILE_PATH: str = ""
    LOG_MAX_BYTES: int = 10 * 1024 * 1024
    LOG_BACKUP_COUNT: int = 5
    AUDIT_ENABLED: bool = True
    ALERT_LOGIN_FAILURE_THRESHOLD: int = 5
    ALERT_ACCESS_DENIED_THRESHOLD: int = 10
    ALERT_LOOKBACK_MINUTES: int = 15
    ALERT_DEDUP_MINUTES: int = 15

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Email
    EMAIL_FROM: str = "no-reply@techpulse.local"
    EMAIL_SUBJECT: str = "Welcome to Tech Pulse"
    SMTP_HOST: str = "sandbox.smtp.mailtrap.io"
    SMTP_PORT: int = 2525
    SMTP_USERNAME: str = "60d6d7ce5e2666"
    SMTP_PASSWORD: str = "2d361b7eddfd39"
    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False
    SMTP_VALIDATE_CERTS: bool = True

    # URLs
    BASE_URL: str = "http://127.0.0.1:8000"
    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = ""

    # Project management
    UPLOAD_ROOT: str = "storage"
    PACKAGE_STORAGE_BACKEND: str = "local"
    PACKAGE_UPLOAD_MAX_SIZE_BYTES: int = 5 * 1024 * 1024 * 1024
    PACKAGE_UPLOAD_CHUNK_SIZE_BYTES: int = 1024 * 1024
    PACKAGE_USER_QUOTA_BYTES: int = 25 * 1024 * 1024 * 1024
    PACKAGE_UPLOAD_RATE_LIMIT: int = 30
    PACKAGE_UPLOAD_RATE_WINDOW_SECONDS: int = 60
    PACKAGE_DOWNLOAD_RATE_LIMIT: int = 120
    PACKAGE_DOWNLOAD_RATE_WINDOW_SECONDS: int = 60

    # Authentication
    ALGORITHM: str = "HS256"
    LOGIN_TOKEN_EXPIRE_MINUTES: int = 30
    EMAIL_TOKEN_EXPIRE_MINUTES: int = 60
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30
    EMAIL_VERIFY_SECRET: str = "dev_email_verify_secret_change_me_1234567890"
    PASSWORD_RESET_SECRET: str = ""
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    REFRESH_REQUIRE_SAME_USER_AGENT: bool = True
    REFRESH_REQUIRE_SAME_IP: bool = False

    # Auth abuse protection
    AUTH_LOGIN_RATE_LIMIT: int = 10
    AUTH_LOGIN_WINDOW_SECONDS: int = 60
    AUTH_REFRESH_RATE_LIMIT: int = 30
    AUTH_REFRESH_WINDOW_SECONDS: int = 60
    AUTH_PASSWORD_RESET_REQUEST_RATE_LIMIT: int = 5
    AUTH_PASSWORD_RESET_REQUEST_WINDOW_SECONDS: int = 300
    AUTH_PASSWORD_RESET_CONFIRM_RATE_LIMIT: int = 10
    AUTH_PASSWORD_RESET_CONFIRM_WINDOW_SECONDS: int = 300

    # Compatibility
    EXPOSE_ACCESS_TOKEN_IN_BODY: bool = False

    # AI
    AI_API_KEY: str = ""
    AI_BASE_URL: str = "https://api.openai.com/v1"
    WHISPER_MODEL: str = "whisper-1"
    SUPPORT_CHAT_MODEL: str = "gpt-4o-mini"
    TRANSCRIPTION_BASE_URL: str = ""

    # Startup superuser seeding
    SUPERUSER_SEED_ENABLED: bool = True
    SUPERUSER_FULL_NAME: str = ""
    SUPERUSER_USERNAME: str = ""
    SUPERUSER_EMAIL: str = ""
    SUPERUSER_PASSWORD: str = ""
    SUPERUSER_UPDATE_PASSWORD_ON_STARTUP: bool = False

    # Session cookies
    ACCESS_COOKIE_NAME: str = "tp_access"
    REFRESH_COOKIE_NAME: str = "tp_refresh"
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"
    COOKIE_DOMAIN: str | None = None
    ACCESS_COOKIE_PATH: str = "/"
    REFRESH_COOKIE_PATH: str = "/api/v1/auth"

    # Email retry
    EMAIL_RETRY_MAX_ATTEMPTS: int = 4
    EMAIL_RETRY_BASE_DELAY_SECONDS: int = 2
    EMAIL_RETRY_MAX_DELAY_SECONDS: int = 30

    # Email verification recovery loop
    EMAIL_RECOVERY_ENABLED: bool = True
    EMAIL_RECOVERY_INTERVAL_SECONDS: int = 120
    EMAIL_RECOVERY_ELIGIBLE_AGE_SECONDS: int = 120
    EMAIL_RECOVERY_MAX_BATCH_SIZE: int = 100
    EMAIL_RECOVERY_MAX_RETRY_COUNT: int = 20
    EMAIL_RECOVERY_BACKOFF_BASE_SECONDS: int = 120
    EMAIL_RECOVERY_BACKOFF_MAX_SECONDS: int = 3600
    EMAIL_RECOVERY_STARTUP_DELAY_SECONDS: int = 15

    @model_validator(mode="after")
    def normalize_and_validate(self) -> "AppSettings":
        self.LOG_LEVEL = (self.LOG_LEVEL or "INFO").upper()
        self.LOG_DIR = _resolve_path(self.LOG_DIR, "logs")
        self.LOG_FILE_PATH = _resolve_path(self.LOG_FILE_PATH, str(Path(self.LOG_DIR) / "app.log"))
        self.SMTP_HOST = _normalize_smtp_host(self.SMTP_HOST)
        self.BACKEND_URL = (self.BACKEND_URL or self.BASE_URL or "http://127.0.0.1:8000").strip()
        self.UPLOAD_ROOT = _resolve_path(self.UPLOAD_ROOT, "storage")
        self.PACKAGE_STORAGE_BACKEND = (self.PACKAGE_STORAGE_BACKEND or "local").lower()
        self.COOKIE_SAMESITE = (self.COOKIE_SAMESITE or "lax").lower()
        self.COOKIE_DOMAIN = (self.COOKIE_DOMAIN or "").strip() or None
        self.PASSWORD_RESET_SECRET = (
            (self.PASSWORD_RESET_SECRET or "").strip()
            or self.EMAIL_VERIFY_SECRET
            or self.SECRET_KEY
        )

        if self.PACKAGE_STORAGE_BACKEND not in {"local", "object"}:
            raise RuntimeError("PACKAGE_STORAGE_BACKEND must be 'local' or 'object'.")
        if self.COOKIE_SAMESITE not in {"lax", "strict", "none"}:
            raise RuntimeError("COOKIE_SAMESITE must be one of: lax, strict, none.")
        return self

    def validate_security(self) -> None:
        _assert_min_secret("SECRET_KEY", self.SECRET_KEY or "")
        _assert_min_secret("EMAIL_VERIFY_SECRET", self.EMAIL_VERIFY_SECRET or "")
        _assert_min_secret("PASSWORD_RESET_SECRET", self.PASSWORD_RESET_SECRET or "")


settings = AppSettings()


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


def _assert_min_secret(name: str, value: str, min_len: int = 32) -> None:
    if not value or len(value.strip()) < min_len:
        raise RuntimeError(f"{name} must be set and at least {min_len} characters long.")
