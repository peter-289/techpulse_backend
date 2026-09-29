"""Import-graph regression test.

``app.infrastructure.database.unit_of_work`` imports the software repositories,
which import the ``app.modules.software_management`` package, whose ``__init__``
eagerly imported the application services, which import ``unit_of_work`` again.
The resulting cycle made ``import app.modules.shared.dependencies`` fail unless
``app.main`` happened to be imported first, so the failure depended on import
order.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

MODULES = [
    "app.modules.shared.dependencies",
    "app.infrastructure.database.unit_of_work",
    "app.modules.resource.resource_service",
    "app.modules.software_management",
    "app.modules.security.audit_middleware",
]


def _run(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_modules_import_in_isolation() -> None:
    for module in MODULES:
        result = _run(f"import {module}")
        assert result.returncode == 0, (
            f"importing {module} on its own failed:\n{result.stdout}\n{result.stderr}"
        )


def test_dependencies_imports_before_app_main() -> None:
    result = _run(
        """
        import app.modules.shared.dependencies as deps
        assert deps.CurrentUser is not None
        print("OK")
        """
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "OK" in result.stdout


def test_software_management_package_still_reexports_its_services() -> None:
    result = _run(
        """
        from app.modules.software_management import (
            CategoryService,
            DownloadService,
            SearchAlgorithm,
            SearchService,
            SoftwareService,
        )
        print("OK")
        """
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "OK" in result.stdout


def test_software_management_package_rejects_unknown_attributes() -> None:
    result = _run(
        """
        import app.modules.software_management as pkg
        try:
            pkg.NotAThing
        except AttributeError:
            print("OK")
        """
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "OK" in result.stdout
