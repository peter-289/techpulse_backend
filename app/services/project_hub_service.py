from __future__ import annotations

import logging
import uuid
from pathlib import Path

from app.core.config import settings
from app.core.unit_of_work import UnitOfWork
from app.exceptions.exceptions import NotFoundError, PermissionError, ValidationError
from app.models.project import Project

logger = logging.getLogger(__name__)


class ProjectHubService:
    ALLOWED_EXTENSIONS = {".zip", ".tar", ".gz", ".rar", ".7z", ".exe", ".msi", ".deb", ".rpm"}
    MAX_FILE_SIZE = 1024 * 1024 * 200  # 200 MB

    def __init__(self, uow: UnitOfWork):
        self.uow = uow
        self.projects_dir = Path(settings.UPLOAD_ROOT) / "projects"
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    def create_project(
        self,
        *,
        user_id: int,
        name: str,
        description: str,
        version: str | None,
        is_public: bool,
        filename: str,
        content: bytes,
    ) -> Project:
        
        cleaned_name = (name or "").strip()
        cleaned_desc = (description or "").strip()
        if not cleaned_name or not cleaned_desc:
            raise ValidationError("Project name and description are required")
        if not content:
            raise ValidationError("Uploaded project file is empty")
        if len(content) > self.MAX_FILE_SIZE:
            raise ValidationError("Project file is too large")

        suffix = Path(filename or "").suffix.lower()
        if suffix not in self.ALLOWED_EXTENSIONS:
            raise ValidationError("Unsupported project file format")

        safe_filename = f"{uuid.uuid4().hex}{suffix}"
        file_path = self.projects_dir / safe_filename
        file_path.write_bytes(content)

        project = Project(
            user_id=user_id,
            name=cleaned_name,
            description=cleaned_desc,
            version=(version or "").strip() or None,
            file_name=filename,
            file_path=str(file_path),
            file_size_bytes=len(content),
            is_public=is_public,
        )
        with self.uow:
            return self.uow.project_repo.add(project)

    def list_projects(self, *, user_id: int, cursor: int | None = None, limit: int = 50) -> list[Project]:
        with self.uow.read_only():
            projects = self.uow.project_repo.list_visible_for_user(user_id=user_id, cursor=cursor, limit=limit)
            logger.debug(
                "Fetched projects page",
                extra={"user_id": user_id, "cursor": cursor, "limit": limit, "count": len(projects)},
            )
            return projects

    def get_project_for_user(self, *, user_id: int, project_id: int) -> Project:
        with self.uow.read_only():
            project = self.uow.project_repo.get_by_id(project_id)
            if not project:
                raise NotFoundError("Project not found")
            if not project.is_public and project.user_id != user_id:
                raise PermissionError("You do not have access to this project")
            return project

    def register_download(self, *, user_id: int, project_id: int) -> Project:
        with self.uow:
            project = self.uow.project_repo.get_by_id(project_id)
            if not project:
                raise NotFoundError("Project not found")
            if not project.is_public and project.user_id != user_id:
                raise PermissionError("You do not have access to this project")
            self.uow.project_repo.increment_download_count(project_id=project.id)
            return project

    def delete_project(self, *, user_id: int, project_id: int) -> None:
        file_path: str | None = None
        with self.uow:
            project = self.uow.project_repo.get_by_id(project_id)
            if not project:
                raise NotFoundError("Project not found")
            if project.user_id != user_id:
                raise PermissionError("Only the owner can delete this project")
            file_path = project.file_path
            self.uow.project_repo.delete(project)
        if file_path:
            try:
                Path(file_path).unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to remove project file", extra={"project_id": project_id})
