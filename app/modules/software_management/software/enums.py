from enum import StrEnum


class SoftwareStatus(StrEnum):
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


class SoftwareVisibility(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
