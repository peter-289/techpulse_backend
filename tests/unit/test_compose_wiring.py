"""Static checks on the deployment wiring.

Docker is not available in CI or in this checkout, so `docker compose config`
never runs and a malformed compose file would only surface at deploy time.
These read the files instead and assert the invariants that matter: the
migration ordering, that nothing runs alembic on the app lifecycle path, that
the volumes the app writes to are pre-created in the image (or they come up
root-owned and the container dies at import), and that every interpolated
variable is actually declared.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "docker-compose.yml"
ENV_EXAMPLE_PATH = ROOT / ".env.example"
DOCKERFILE_PATH = ROOT / "Dockerfile"
ENTRYPOINT_PATH = ROOT / "docker-entrypoint.sh"


@pytest.fixture(scope="module")
def raw_compose() -> str:
    return COMPOSE_PATH.read_text()


@pytest.fixture(scope="module")
def compose(raw_compose: str) -> dict:
    return yaml.safe_load(raw_compose)


@pytest.fixture(scope="module")
def services(compose: dict) -> dict:
    return compose.get("services", {})


@pytest.fixture(scope="module")
def declared_env_vars() -> set[str]:
    """Variable names declared in the single root .env.example."""
    names = set()
    for line in ENV_EXAMPLE_PATH.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            names.add(stripped.partition("=")[0].strip())
    return names


class TestMigrationLifecycle:
    def test_migrate_is_its_own_service(self, services: dict) -> None:
        assert "migrate" in services, "no separate migration step exists"
        entrypoint = str(services["migrate"].get("entrypoint", ""))
        assert "alembic" in entrypoint
        assert "upgrade" in entrypoint

    def test_migrate_is_not_long_running(self, services: dict) -> None:
        """It exits when done; a restart policy would bring it back."""
        assert services["migrate"].get("restart") in ("no", '"no"')

    def test_api_waits_for_migrations_to_complete(self, services: dict) -> None:
        deps = services["api"].get("depends_on") or {}
        assert deps.get("migrate") == {"condition": "service_completed_successfully"}, (
            "api must not start before migrations finish successfully"
        )

    def test_migrate_waits_for_the_database(self, services: dict) -> None:
        deps = services["migrate"].get("depends_on") or {}
        assert deps.get("db", {}).get("condition") == "service_healthy"

    def test_nothing_waits_on_a_service_that_restarts(self, services: dict) -> None:
        for name, svc in services.items():
            for dep, cond in (svc.get("depends_on") or {}).items():
                if cond != "service_completed_successfully":
                    continue
                target = services.get(dep, {})
                assert target.get("restart") in ("no", '"no"'), (
                    f"{name} waits for {dep} to exit, but its restart policy is "
                    f"{target.get('restart')!r}"
                )

    def test_app_startup_does_not_run_alembic(self) -> None:
        """docker-entrypoint.sh starts the web server and nothing else."""
        executing = [
            line.strip()
            for line in ENTRYPOINT_PATH.read_text().splitlines()
            if line.strip()
            and not line.strip().startswith("#")
            and "alembic" in line
        ]
        assert not executing, (
            "docker-entrypoint.sh invokes alembic: " + "; ".join(executing)
        )

    def test_no_startup_run_migrations_switch_remains(self) -> None:
        """The dead config field and its template entry both go.

        Matched as a field declaration, not a bare substring: the comment
        explaining why it was removed still names it.
        """
        config_source = (ROOT / "app/core/config.py").read_text()
        assert not re.search(
            r"^\s*STARTUP_RUN_MIGRATIONS\s*:", config_source, re.MULTILINE
        ), "STARTUP_RUN_MIGRATIONS is still declared as a settings field"
        assert "STARTUP_RUN_MIGRATIONS" not in ENV_EXAMPLE_PATH.read_text()


class TestWritableVolumes:
    def test_the_image_pre_creates_every_mounted_app_path(
        self, raw_compose: str
    ) -> None:
        """A named volume inherits ownership from the image path.

        Docker seeds a fresh named volume from whatever the image has at that
        path. If the path does not exist, the volume is created empty and
        root-owned, and a non-root process cannot write to it -- which for this
        image means dying in logging_setup.py at import, before uvicorn starts.
        """
        dockerfile = DOCKERFILE_PATH.read_text()
        mounts = re.findall(
            r"^\s*-\s*(\w+):(/app/[\w/]+)\s*$", raw_compose, re.MULTILINE
        )
        assert mounts, "no /app volumes found; the parsing may have drifted"
        for volume, path in mounts:
            assert path in dockerfile, (
                f"volume {volume} mounts {path}, which the Dockerfile never "
                f"creates -- it would come up root-owned"
            )

    def test_the_app_runs_as_a_non_root_user(self) -> None:
        dockerfile = DOCKERFILE_PATH.read_text()
        assert "USER appuser" in dockerfile

    def test_the_upload_root_and_its_mount_are_the_same_directory(
        self, compose: dict
    ) -> None:
        """Where artifacts are written, and where they are mounted, must be one path.

        These are two separate keys in the compose file, and nothing in the
        application connects them: ``UPLOAD_ROOT`` is read by ``LocalStorage`` and
        the ``volumes:`` entry is read by Docker. If they drift apart the
        container still starts, still passes every health check, and writes every
        artifact into the container layer -- where they are silently destroyed the
        next time the image is replaced. Nothing else in the suite would notice,
        which is why it is asserted here.

        This is the invariant behind "artifacts live at the persistent path": the
        named volume is what makes them survive, and it only helps if the process
        is actually writing to it.
        """
        api = compose["services"]["api"]
        environment = api.get("environment", {})
        mounts = [
            mount
            for mount in api.get("volumes", [])
            if isinstance(mount, str) and mount.split(":")[0] == "api_storage"
        ]

        assert mounts, "the api_storage volume is no longer mounted on the api service"
        assert len(mounts) == 1, f"api_storage is mounted more than once: {mounts}"

        mount_path = mounts[0].split(":")[1]
        upload_root = environment.get("UPLOAD_ROOT")

        assert upload_root == mount_path, (
            f"UPLOAD_ROOT is {upload_root!r} but api_storage is mounted at "
            f"{mount_path!r}; artifacts would be written outside the volume and "
            f"lost when the container is replaced"
        )

    def test_the_upload_root_is_where_the_adapter_actually_reads_from(self) -> None:
        """``UPLOAD_ROOT`` is the only thing that decides the adapter's root, so
        the setting name in compose and the one in config cannot drift apart
        silently either."""
        config = (ROOT / "app" / "core" / "config.py").read_text()
        container = (ROOT / "app" / "modules" / "shared" / "container.py").read_text()

        assert re.search(r"^\s*UPLOAD_ROOT\s*:", config, re.MULTILINE), (
            "UPLOAD_ROOT is no longer declared in settings"
        )
        assert "storage_root=settings.UPLOAD_ROOT" in container, (
            "the storage adapter is no longer rooted at settings.UPLOAD_ROOT"
        )

    def test_the_artifacts_volume_is_a_named_volume_not_a_host_path(
        self, compose: dict
    ) -> None:
        """A bind mount would put artifacts on the host filesystem, whose
        ownership and lifetime are the deployer's problem rather than Docker's."""
        assert "api_storage" in compose.get("volumes", {}), (
            "api_storage is not declared as a named volume"
        )
        for mount in compose["services"]["api"].get("volumes", []):
            if isinstance(mount, str) and mount.startswith("api_storage:"):
                source = mount.split(":")[0]
                assert not source.startswith((".", "/", "~")), (
                    f"artifacts are bind-mounted from {source!r} instead of a named volume"
                )


class TestSingleRootEnvFile:
    def test_every_interpolated_variable_is_declared(
        self, raw_compose: str, declared_env_vars: set[str]
    ) -> None:
        """Compose interpolates the whole file, active services or not."""
        missing = []
        for match in re.finditer(
            r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-?]?)([^}]*)\}", raw_compose
        ):
            var, modifier = match.group(1), match.group(2)
            if modifier:  # ${VAR:-default} or ${VAR:?message}
                continue
            if var not in declared_env_vars:
                missing.append(var)
        assert not missing, (
            "interpolated but not declared in .env.example: "
            + ", ".join(sorted(set(missing)))
        )

    def test_variables_marked_required_are_declared(
        self, raw_compose: str, declared_env_vars: set[str]
    ) -> None:
        required = {
            m.group(1)
            for m in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*):[?-]", raw_compose)
        }
        assert required, "expected at least one ${VAR:?...} guard"
        assert required <= declared_env_vars, (
            "required but undeclared: " + ", ".join(sorted(required - declared_env_vars))
        )

    def test_the_app_service_receives_the_root_env_file(self, services: dict) -> None:
        for name in ("api", "migrate"):
            assert ".env" in (services[name].get("env_file") or []), (
                f"{name} does not receive the root .env"
            )

    def test_the_database_does_not_receive_application_secrets(
        self, services: dict
    ) -> None:
        """postgres is configured by explicit keys, not the whole file."""
        env_file = services["db"].get("env_file")
        assert env_file is None, "db should list only the variables it needs"
        keys = set(services["db"].get("environment", {}))
        assert keys == {"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"}


class TestDevOnlyServices:
    @pytest.mark.parametrize("name", ["mailhog", "pgadmin"])
    def test_local_dev_services_are_profile_gated(self, services: dict, name: str) -> None:
        assert "dev" in (services.get(name, {}).get("profiles") or []), (
            f"{name} is local-dev only and must not start under `docker compose up`"
        )

    def test_pgadmin_password_is_not_committed(self, raw_compose: str) -> None:
        """A real password was committed here before, at 241f483."""
        compose = yaml.safe_load(raw_compose)
        password = compose["services"]["pgadmin"]["environment"][
            "PGADMIN_DEFAULT_PASSWORD"
        ]
        assert "PGADMIN_PASSWORD" in password
        assert "?" in password or ":-" in password, (
            "PGADMIN_DEFAULT_PASSWORD must be sourced from the environment"
        )

    def test_no_literal_credentials_anywhere_in_compose(self, raw_compose: str) -> None:
        assert "MwakiPeter" not in raw_compose


class TestSharedImage:
    def test_api_and_migrate_are_built_once(self, services: dict) -> None:
        images = {services[n].get("image") for n in ("api", "migrate")}
        assert len(images) == 1 and None not in images

    def test_both_services_carry_the_build_definition(self, services: dict) -> None:
        """The `<<: *backend-image` merge must actually land."""
        for name in ("api", "migrate"):
            assert "build" in services[name], f"{name} lost the shared build anchor"