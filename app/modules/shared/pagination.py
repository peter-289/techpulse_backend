from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class OffsetPage(BaseModel, Generic[T]):
    """Offset-based paginated response.

    items: page items
    total: total number of records across all pages
    limit: page size
    offset: starting offset for this page
    has_next: whether a next page exists
    has_prev: whether a previous page exists
    """

    items: list[T]
    total: int
    limit: int
    offset: int
    has_next: bool
    has_prev: bool

