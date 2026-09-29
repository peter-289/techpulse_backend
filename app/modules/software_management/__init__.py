"""Software management feature package.

Service classes are resolved lazily via :pep:`562` module ``__getattr__`` rather
than imported eagerly. Eager imports here created a cycle:

    app.infrastructure.database.unit_of_work
      -> ...software_management.infrastructure...sqlalchemy_software_repository
        -> app.modules.software_management (package __init__)
          -> application.services.category_service
            -> app.infrastructure.database.unit_of_work  (partially initialised)

which made ``import app.modules.shared.dependencies`` fail unless ``app.main``
happened to be imported first. Names are still re-exported, so existing
``from app.modules.software_management import SoftwareService`` call sites keep
working, but only pay the import cost when actually used.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters at runtime
    from .application.services.category_service import CategoryService
    from .application.services.download_service import DownloadService
    from .application.services.search_algorithm import SearchAlgorithm
    from .application.services.search_service import SearchService
    from .application.services.software_service import SoftwareService

__all__ = [
    "CategoryService",
    "DownloadService",
    "SearchAlgorithm",
    "SearchService",
    "SoftwareService",
]

_LAZY_IMPORTS = {
    "CategoryService": ".application.services.category_service",
    "DownloadService": ".application.services.download_service",
    "SearchAlgorithm": ".application.services.search_algorithm",
    "SearchService": ".application.services.search_service",
    "SoftwareService": ".application.services.software_service",
}


def __getattr__(name: str):
    module_path = _LAZY_IMPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from importlib import import_module

    module = import_module(module_path, __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY_IMPORTS})
