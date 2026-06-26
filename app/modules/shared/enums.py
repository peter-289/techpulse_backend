from enum import auto, StrEnum

# Gender Enum
class GenderEnum(StrEnum):
    MALE = "MALE"
    FEMALE = "FEMALE"
    NON_BINARY = "NON_BINARY"
    PREFER_NOT_TO_SAY = "PREFER_NOT_TO_SAY"


class UserStatus(StrEnum):
    UNAPPROVED = "UNAPPROVED"
    VERIFIED = "VERIFIED"
    SUSPENDED = "SUSPENDED"  


class RoleEnum(StrEnum): 
    ADMIN = "ADMIN"
    USER = "USER"


class AppState(StrEnum):
    BOOTING = auto()
    CONFIG_VALIDATED = auto()
    DB_MIGRATIONS_RUNNING = auto()
    DB_READY = auto()
    SEEDING_STARTED = auto()
    SEEDING_COMPLETE = auto()
    SERVICES_READY = auto()
    RUNNING = auto()
    FAILED = auto()


class AuditEventType(StrEnum):
    LOGIN_FAILED = "auth.login.failed"
    ACCESS_DENIED = "auth.access.denied"


class AlertRuleCode(StrEnum):
    AUTH_BRUTE_FORCE_IP = "AUTH_BRUTE_FORCE_IP"
    EXCESSIVE_FORBIDDEN_REQUESTS = "EXCESSIVE_FORBIDDEN_REQUESTS"


class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CookieConsent(StrEnum):
    ACCEPTED = "accepted"
    DECLINED = "declined"


class SoftwareVisibility(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


class KnownCategorySlug(StrEnum):
    DEV_TOOLS = "dev-tools"
    PRODUCTIVITY = "productivity"
    DESIGN = "design"
    EDUCATION = "education"
    ENTERTAINMENT = "entertainment"
    FINANCE = "finance"
    HEALTH_FITNESS = "health-fitness"
    LIFESTYLE = "lifestyle"
    NEWS = "news"
    SOCIAL_MEDIA = "social-media"
    UTILITIES = "utilities"


class PurchaseStatus(StrEnum):
    ACTIVE = "active"
    REFUNDED = "refunded"
    CANCELED = "canceled"


class PaymentStatus(StrEnum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"


class SoftwareStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"
    DELETED = "deleted"


class VersionStatus(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    REVOKED = "revoked" 
    DELETED = "deleted"
    

class ArtifactStatus(StrEnum):
    UPLOADING = "uploading"
    ACTIVE = "active"
    DELETED = "deleted"
    QUARANTINED = "quarantined"


class AccessPolicy(StrEnum):
    FREE = "free"
    PURCHASE_REQUIRED = "purchase_required"
    OWNER_ONLY = "owner_only"


class PaymentProvider(StrEnum):
    MPESA = "mpesa"
    STRIPE = "stripe"
    PAYPAL = "paypal"

class PaymentResourceType(StrEnum):
    SOFTWARE = "software"
    SUBSCRIPTION = "subscription"
    LICENCE = "licence" 

