"""Layering and static-safety rules for M3: cli -> services -> storage/domain.

The AST checks cover imports (no upward or sideways dependencies), SQL construction and
direct database access.
"""

import ast
import sys
from pathlib import Path

import pytest

from tests.unit.storage.test_storage_security import sql_violations

SRC = Path(__file__).resolve().parents[2] / "src" / "soerm"
STDLIB = set(sys.stdlib_module_names)

# package -> soerm sub-packages it may import
ALLOWED_INTERNAL: dict[str, set[str]] = {
    "domain": set(),
    "config": {"domain"},
    "importers": {"domain"},
    "outputs": {"domain"},
    "storage": {"domain"},
    "services": {"config", "domain", "importers", "outputs", "storage"},
    "cli": {"domain", "services", "tui"},
    "tui": {"domain", "services"},
}
# standard-library modules each upper layer may use
CLI_STDLIB = {
    "argparse", "collections", "datetime", "json", "re", "sys", "typing", "unicodedata",
}  # fmt: skip
SERVICES_STDLIB = {
    "collections", "contextlib", "dataclasses", "datetime", "enum", "pathlib", "re", "typing",
    "unicodedata",
}  # fmt: skip


def modules(path: Path) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"relative import in {path}"
            found.append((node.lineno, node.module or ""))
    return found


def files(package: str) -> list[Path]:
    return sorted((SRC / package).glob("*.py"))


@pytest.mark.parametrize("package", sorted(ALLOWED_INTERNAL))
def test_internal_dependencies_follow_the_layering(package: str) -> None:
    problems: list[str] = []
    for path in files(package):
        for line, name in modules(path):
            parts = name.split(".")
            if parts[0] != "soerm" or len(parts) < 2:
                continue
            target = parts[1]
            if target != package and target not in ALLOWED_INTERNAL[package]:
                problems.append(f"{path.name}:{line} imports soerm.{target}")
    assert not problems, problems


@pytest.mark.parametrize("package", ["domain", "storage"])
def test_lower_layers_never_import_upper_layers(package: str) -> None:
    upper = {"services", "cli", "importers", "outputs"}
    for path in files(package):
        for _, name in modules(path):
            assert not (name.startswith("soerm.") and name.split(".")[1] in upper), (path, name)


def test_domain_depends_on_nothing_but_itself() -> None:
    for path in files("domain"):
        for _, name in modules(path):
            top = name.split(".")[0]
            if top == "soerm":
                assert name.split(".")[1] == "domain", (path.name, name)
            assert top not in {"sqlite3", "yaml", "os", "pathlib"}, (path.name, name)


def test_cli_uses_only_the_service_layer_for_data() -> None:
    for path in files("cli"):
        for line, name in modules(path):
            top = name.split(".")[0]
            assert not name.startswith("soerm.storage"), f"{path.name}:{line} imports storage"
            assert top not in {"sqlite3", "os", "pathlib", "shutil", "tempfile", "io"}, (
                f"{path.name}:{line}: {name}"
            )
            if top != "soerm":
                assert top in CLI_STDLIB, f"{path.name}:{line}: unexpected import {name}"


def test_services_use_only_the_standard_library_they_need() -> None:
    for path in files("services"):
        for line, name in modules(path):
            top = name.split(".")[0]
            if top != "soerm":
                assert top in SERVICES_STDLIB, f"{path.name}:{line}: unexpected import {name}"
                assert top != "sqlite3"


def test_standard_library_allowlists_contain_only_stdlib() -> None:
    assert CLI_STDLIB <= STDLIB
    assert SERVICES_STDLIB <= STDLIB


@pytest.mark.parametrize("package", ["cli", "services"])
def test_no_database_calls_outside_storage(package: str) -> None:
    for path in files(package):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {
                    "execute", "executemany", "executescript", "cursor", "commit", "rollback",
                    "connect", "row_factory",
                }, f"{path.name}:{node.lineno}: .{node.attr}"  # fmt: skip


def test_cli_never_touches_repositories_directly() -> None:
    for path in files("cli"):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("Repository", "CounterRepository", "open_database", "WorkspaceLock"):
            assert forbidden not in text, (path.name, forbidden)


def test_cli_does_not_write_files_or_use_processes() -> None:
    for path in files("cli"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                assert node.id not in {"open", "exec", "eval", "compile", "__import__"}, path.name
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"write_text", "write_bytes", "mkdir", "open", "unlink"}, (
                    path.name,
                    node.attr,
                )


@pytest.mark.parametrize("package", ["cli", "services", "storage"])
def test_no_sql_is_built_from_values(package: str) -> None:
    for path in files(package):
        assert sql_violations(path.read_text(encoding="utf-8")) == [], path.name


@pytest.mark.parametrize("package", ["cli", "services"])
def test_no_sql_text_at_all_above_storage(package: str) -> None:
    keywords = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "PRAGMA ", "CREATE TABLE")
    for path in files(package):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not any(node.value.upper().startswith(k) for k in keywords), (
                    path.name,
                    node.lineno,
                )


def test_no_network_or_dynamic_code_anywhere_in_m3_layers() -> None:
    banned = {
        "socket", "ssl", "urllib", "http", "requests", "httpx", "subprocess", "importlib",
        "runpy", "pickle", "marshal", "shelve", "yaml", "ctypes", "asyncio", "multiprocessing",
    }  # fmt: skip
    for package in ("cli", "services"):
        for path in files(package):
            for line, name in modules(path):
                assert name.split(".")[0] not in banned, f"{path.name}:{line}: {name}"
