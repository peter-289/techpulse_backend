from pydantic import BaseModel, Field


class SoftwareCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str = Field(min_length=1)
    visibility: str = "public"


class SoftwareVersionCreate(BaseModel):
    number: str = Field(min_length=5, max_length=64)
    release_notes: str = ""


class SoftwareRead(BaseModel):
    id: str
    name: str
    description: str
    owner_id: int
    is_public: bool
    price_cents: int = 0
    currency: str = "USD"
    viewer_has_access: bool = False
    category: str
    latest_version: str | None
    download_count: int
    created_at: str
    updated_at: str


class SoftwareVersionRead(BaseModel):
    id: str
    software_id: str
    version: str
    is_published: bool
    status: str
    download_count: int
    release_notes: str
    created_at: str
    published_at: str | None
    file_hash: str | None
    size_bytes: int | None
    content_type: str | None
    file_name: str | None
    artifact_status: str | None = None
    quarantine_reason: str | None = None


class SoftwareUploadResponse(BaseModel):
    id: str
    software_id: str
    version_id: str
    version: str
    size_bytes: int
    sha256: str


class SoftwarePricingUpdate(BaseModel):
    price_cents: int = Field(ge=0, le=10_000_000)
    currency: str = Field(default="USD", min_length=3, max_length=3)


class SoftwareCheckoutRead(BaseModel):
    id: str
    software_id: str
    buyer_id: int
    owner_id: int
    amount_cents: int
    currency: str
    status: str
    provider: str
    provider_reference: str | None = None
    client_secret: str | None = None
    checkout_url: str | None = None
    created_at: str
    completed_at: str | None = None


class SoftwareSummary(BaseModel):
    total_packages: int
    total_versions: int
    published_versions: int
    total_downloads: int
