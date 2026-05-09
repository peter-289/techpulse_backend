from enum import Enum, auto, StrEnum

# Gender Enum
class GenderEnum(str, Enum):
    MALE = "MALE"
    FEMALE = "FEMALE"
    NON_BINARY = "NON_BINARY"
    PREFER_NOT_TO_SAY = "PREFER_NOT_TO_SAY"

class UserStatus(str, Enum):
    UNAPPROVED = "UNAPPROVED"
    VERIFIED = "VERIFIED"
    SUSPENDED = "SUSPENDED"  

class RoleEnum(str, Enum): 
    ADMIN = "ADMIN"
    USER = "USER"


class AppState(Enum):
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
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
