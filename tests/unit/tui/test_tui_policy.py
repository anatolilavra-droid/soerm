"""The TUI is a window onto services: no storage, SQL, processes, network or file writes."""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[3] / "src" / "soerm" / "tui"
FILES = sorted(SRC.glob("*.py"))
ALLOWED_THIRD_PARTY = {"textual", "rich"}
ALLOWED_STDLIB = {"collections", "dataclasses", "datetime", "os", "sys", "textwrap", "typing"}
ALLOWED_INTERNAL = {"domain", "services", "tui"}
FORBIDDEN_NAMES = {"open", "exec", "eval", "compile", "__import__"}
FORBIDDEN_ATTRIBUTES = {
    "execute", "executemany", "executescript", "cursor", "commit", "rollback", "connect",
    "write_text", "write_bytes", "mkdir", "unlink", "rmdir", "rename", "replace", "system",
    "popen", "save_screenshot", "export_screenshot", "fork", "spawn", "environ_set", "putenv",
}  # fmt: skip


def modules(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(node.lineno, alias.name) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            found.append((node.lineno, node.module or ""))
    return found


def test_the_package_is_found() -> None:
    assert {p.name for p in FILES} >= {"app.py", "data.py", "terminal.py", "theme.py"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_imports_are_limited(path: Path) -> None:
    for line, name in modules(ast.parse(path.read_text(encoding="utf-8"))):
        parts = name.split(".")
        top = parts[0]
        if top == "soerm":
            assert parts[1] in ALLOWED_INTERNAL, f"{path.name}:{line}: {name}"
        else:
            assert top in ALLOWED_THIRD_PARTY | ALLOWED_STDLIB, f"{path.name}:{line}: {name}"


def test_only_the_terminal_probe_touches_the_environment() -> None:
    for path in FILES:
        uses = {name.split(".")[0] for _, name in modules(ast.parse(path.read_text("utf-8")))}
        if path.name != "terminal.py":
            assert not uses & {"os"}, path.name


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_dynamic_code_file_writes_or_sql(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            assert node.id not in FORBIDDEN_NAMES, f"{path.name}:{node.lineno}: {node.id}"
        if isinstance(node, ast.Attribute):
            assert node.attr not in FORBIDDEN_ATTRIBUTES, f"{path.name}:{node.lineno}: {node.attr}"
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            upper = node.value.upper()
            assert not upper.startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "PRAGMA ")), (
                path.name,
                node.lineno,
            )


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_service_mutation_is_called(path: Path) -> None:
    mutating = (
        "create_", "update_", "transition_", "load_playbook", "attach_", "complete_step",
        "request_", "approve", "reject", "expire_", "recalculate", "import_", "apply_",
        "generate_report", "add_note", "link_",
    )  # fmt: skip
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            assert not name.startswith(mutating), f"{path.name}:{node.lineno}: {name}"


def test_data_uses_only_read_services() -> None:
    tree = ast.parse((SRC / "data.py").read_text(encoding="utf-8"))
    used = {
        f"{node.value.id}.{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
    }
    services = {u for u in used if u.split(".")[0] in {"assets", "findings", "incidents", "tasks",
                "approvals", "playbooks", "reports", "audit_check"}}  # fmt: skip
    assert services == {
        "assets.list_assets",
        "findings.list_findings",
        "incidents.list_incidents",
        "tasks.list_tasks",
        "approvals.list_approvals",
        "playbooks.playbook_status",
        "playbooks.list_playbooks",
        "reports.display_sanitizer",
        "reports.build_workspace_report",
        "audit_check.verify_workspace_audit",
    }
