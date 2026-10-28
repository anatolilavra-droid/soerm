"""Static rules for the storage package: no dynamic SQL, no dynamic code, narrow imports."""

import ast
import re
from pathlib import Path

import pytest

from tests.unit.storage.conftest import PROJECT_ROOT

STORAGE = PROJECT_ROOT / "src" / "soerm" / "storage"
SOURCES = sorted(STORAGE.glob("*.py"))

SQL_WORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|PRAGMA|BEGIN|SAVEPOINT|RELEASE|ROLLBACK|"
    r"WHERE|VALUES|FROM)\b",
    re.IGNORECASE,
)
EXECUTE_METHODS = {"execute", "executemany", "executescript"}
FORBIDDEN_MODULES = {
    "yaml", "pickle", "cPickle", "marshal", "shelve", "dill", "socket", "ssl", "urllib",
    "http", "ftplib", "smtplib", "requests", "httpx", "subprocess", "importlib", "runpy",
    "ctypes", "multiprocessing", "asyncio", "pty", "shlex", "tempfile", "shutil",
}  # fmt: skip
ALLOWED_THIRD_PARTY: set[str] = set()
FORBIDDEN_SOERM = {"cli", "services", "importers", "config"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open", "input", "breakpoint"}
OS_ALLOWED_IN = {"connection.py", "lock.py"}


def line_of(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 0))


def parse(source: str) -> ast.Module:
    return ast.parse(source)


def is_sql_text(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and SQL_WORDS.search(node.value) is not None
    )


def contains_sql_text(node: ast.AST) -> bool:
    return any(is_sql_text(child) for child in ast.walk(node))


def literal_tables(tree: ast.Module) -> set[str]:
    """Names of module-level tuples made only of string literals."""
    tables: set[str] = set()
    for node in tree.body:
        value = node.value if isinstance(node, ast.Assign | ast.AnnAssign) else None
        if isinstance(value, ast.Tuple) and all(is_str_constant(e) for e in value.elts):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]  # type: ignore[attr-defined]
            tables.update(t.id for t in targets if isinstance(t, ast.Name))
    return tables


def is_str_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_static_sql(node: ast.AST, tables: set[str]) -> bool:
    """A literal, a choice between literals, a named constant or an index into a literal table."""
    if is_str_constant(node) or isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.IfExp):
        return is_static_sql(node.body, tables) and is_static_sql(node.orelse, tables)
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id in tables
    )


def sql_violations(source: str) -> list[str]:
    """Constructs that build SQL at run time or pass non-literal SQL to ``execute``."""
    found: list[str] = []
    tree = parse(source)
    tables = literal_tables(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr) and contains_sql_text(node):
            found.append(f"{line_of(node)}: f-string with SQL")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            if contains_sql_text(node):
                found.append(f"{line_of(node)}: SQL built with an operator")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format" and contains_sql_text(node.func.value):
                found.append(f"{line_of(node)}: SQL built with format()")
            if node.func.attr == "executescript":
                found.append(f"{line_of(node)}: executescript")
            if (
                node.func.attr in EXECUTE_METHODS
                and node.args
                and not is_static_sql(node.args[0], tables)
            ):
                found.append(f"{line_of(node)}: non-literal SQL passed to {node.func.attr}")
    return found


def module_violations(source: str, *, file_name: str) -> list[str]:
    found: list[str] = []
    for node in ast.walk(parse(source)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                found.append(f"{line_of(node)}: relative import")
            names = [node.module or ""]
        for name in names:
            top = name.split(".")[0]
            if top in FORBIDDEN_MODULES:
                found.append(f"{line_of(node)}: forbidden module {name}")
            elif top == "os" and file_name not in OS_ALLOWED_IN:
                found.append(f"{line_of(node)}: os outside the safe file modules")
            elif top == "soerm":
                parts = name.split(".")
                if len(parts) > 1 and parts[1] in FORBIDDEN_SOERM:
                    found.append(f"{line_of(node)}: forbidden dependency {name}")
        if isinstance(node, ast.Call):
            func = node.func
            called = func.id if isinstance(func, ast.Name) else ""
            if called in FORBIDDEN_CALLS:
                found.append(f"{line_of(node)}: call to {called}")
            if isinstance(func, ast.Attribute) and func.attr in {
                "system",
                "popen",
                "load_extension",
            }:
                found.append(f"{line_of(node)}: call to .{func.attr}")
    return found


# ---- the scanner itself works ---------------------------------------------------------------


@pytest.mark.parametrize(
    "snippet",
    [
        'c.execute(f"SELECT * FROM t WHERE a = {x}")',
        'c.execute("SELECT * FROM t WHERE a = " + x)',
        "c.execute(\"SELECT * FROM t WHERE a = '%s'\" % x)",
        'c.execute("SELECT * FROM t WHERE a = {}".format(x))',
        'q = "DELETE FROM t WHERE a = " + x',
        "c.executescript(script)",
        "c.execute(build(x))",
        'c.execute("SELECT %s" % x)',
    ],
)
def test_scanner_flags_dynamic_sql(snippet: str) -> None:
    assert sql_violations(snippet)


@pytest.mark.parametrize(
    "snippet",
    [
        'c.execute("SELECT * FROM t WHERE a = ?", (x,))',
        'c.execute("SELECT * FROM t WHERE a = :a", {"a": x})',
        "c.execute(STATEMENT)",
        'message = "value " + name',
        'c.execute("SELECT "\n  "1")',
    ],
)
def test_scanner_accepts_static_sql(snippet: str) -> None:
    assert sql_violations(snippet) == []


@pytest.mark.parametrize(
    "snippet",
    [
        "import yaml",
        "import pickle",
        "from urllib import request",
        "import subprocess",
        "from soerm.cli import main",
        "from soerm.services import x",
        "from . import x",
        "eval('1')",
        "open('f')",
        "__import__('os')",
        "import importlib",
        "conn.enable_load_extension(True)\nconn.load_extension('x')",
        "import os",
    ],
)
def test_scanner_flags_forbidden_constructs(snippet: str) -> None:
    assert module_violations(snippet, file_name="x.py")


def test_scanner_accepts_allowed_constructs() -> None:
    source = (
        "import sqlite3\nimport json\nfrom soerm.domain import Asset\n"
        "from soerm.storage.errors import X"
    )
    assert module_violations(source, file_name="x.py") == []
    assert module_violations("import os", file_name="lock.py") == []


# ---- the real package -----------------------------------------------------------------------


def test_storage_sources_are_found() -> None:
    names = {path.name for path in SOURCES}
    assert {"connection.py", "migrations.py", "audit.py", "lock.py", "assets.py"} <= names


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_no_dynamic_sql(path: Path) -> None:
    assert sql_violations(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_imports_and_calls(path: Path) -> None:
    assert module_violations(path.read_text(encoding="utf-8"), file_name=path.name) == []


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_only_known_third_party_and_internal_imports(path: Path) -> None:
    import sys

    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            tops = {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            tops = {(node.module or "").split(".")[0]}
        else:
            continue
        for top in tops:
            assert top in stdlib or top in {"soerm", *ALLOWED_THIRD_PARTY}, (path.name, top)


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_no_yaml_or_pickle_text(path: Path) -> None:
    text = path.read_text(encoding="utf-8").lower()
    assert "yaml" not in text
    assert "pickle" not in text


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_storage_never_calls_model_construct(path: Path) -> None:
    for node in ast.walk(parse(path.read_text(encoding="utf-8"))):
        assert not (isinstance(node, ast.Attribute) and node.attr == "model_construct")


def test_scanner_rejects_a_table_that_is_not_all_literals() -> None:
    source = "T = ('A', x)\nc.execute(T[0])"
    assert sql_violations(source)
    assert sql_violations("T = ('A', 'B')\nc.execute(T[0])") == []
    assert sql_violations("c.execute('A' if f else other())")
