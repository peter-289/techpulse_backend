from enum import Enum, auto

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