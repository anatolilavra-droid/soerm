"""Static policy: production code must stay offline, process-free and I/O-free (M0).

The AST scanner complements ruff's TID251 (banned-api). It resolves plain imports, import
aliases (``import x as y``), submodule imports and from-imports. Later milestones relax
only the filesystem group, deliberately and in this file (see ``MODULE_ALLOWANCES``).
"""

import ast
import fnmatch
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src" / "soerm"

NETWORK_MODULES = frozenset(
    {
        "socket", "ssl", "selectors", "asyncio", "urllib", "http", "ftplib", "smtplib",
        "poplib", "imaplib", "telnetlib", "nntplib", "xmlrpc", "socketserver", "wsgiref",
        "requests", "httpx", "aiohttp", "urllib3", "websockets",
    }
)  # fmt: skip
PROCESS_MODULES = frozenset({"subprocess"})
DYNAMIC_CODE_MODULES = frozenset(
    {"importlib", "runpy", "ctypes", "builtins", "pickle", "marshal", "shelve"}
)
# M0 has no filesystem or database I/O at all.
FILESYSTEM_MODULES = frozenset(
    {
        "os", "pathlib", "shutil", "tempfile", "glob", "io", "fcntl", "mmap", "zipfile",
        "tarfile", "gzip", "bz2", "lzma", "fileinput", "linecache", "sqlite3", "dbm",
    }
)  # fmt: skip

# Deliberate, narrow exceptions to the filesystem group, per production file (M2: storage).
# Network, process and dynamic-code modules are never allowed anywhere.
MODULE_ALLOWANCES: dict[str, frozenset[str]] = {
    "storage/connection.py": frozenset({"sqlite3", "os", "pathlib"}),
    "storage/lock.py": frozenset({"os", "pathlib", "fcntl"}),
    "storage/*.py": frozenset({"sqlite3", "pathlib"}),
    # M3: the workspace path is a ``Path``; services never open files or sockets themselves.
    "services/workspace.py": frozenset({"pathlib"}),
    "services/redaction.py": frozenset({"pathlib"}),
    # M4: the only code that reads the configuration file.
    "config/loader.py": frozenset({"os", "pathlib"}),
    # M5: the only importer module that touches the filesystem.
    "importers/safe_file.py": frozenset({"os", "pathlib"}),
    # M10: the only module that writes a generated file.
    "outputs/safe_write.py": frozenset({"os", "pathlib"}),
    # M13: the terminal probe reads the size of the terminal; nothing else in the UI does.
    "tui/terminal.py": frozenset({"os"}),
}

FORBIDDEN_MODULES = NETWORK_MODULES | PROCESS_MODULES | DYNAMIC_CODE_MODULES | FILESYSTEM_MODULES
FORBIDDEN_BUILTINS = frozenset(
    {"eval", "exec", "compile", "open", "__import__", "breakpoint", "__builtins__"}
)
FORBIDDEN_DUNDER_ATTRIBUTES = frozenset(
    {"__import__", "__builtins__", "__globals__", "__subclasses__"}
)
FORBIDDEN_MEMBERS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("sys", "modules"),
        ("sys", "meta_path"),
        ("sys", "path_hooks"),
        ("yaml", "load"),
        ("yaml", "unsafe_load"),
        ("yaml", "full_load"),
    }
)


@dataclass(frozen=True)
class Violation:
    """A policy violation found in a source fragment."""

    line: int
    detail: str


def _root(dotted: str) -> str:
    return dotted.split(".", 1)[0]


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    """Map names bound by ``import`` statements to the module they refer to."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[_root(alias.name)] = _root(alias.name)
    return aliases


def allowed_modules_for(relative_path: str) -> frozenset[str]:
    """Modules a production file may import despite the filesystem ban."""
    allowed: set[str] = set()
    for pattern, modules in MODULE_ALLOWANCES.items():
        if fnmatch.fnmatch(relative_path, pattern):
            allowed |= modules
    return frozenset(allowed & FILESYSTEM_MODULES)


def find_violations(source: str, allowed: frozenset[str] = frozenset()) -> list[Violation]:
    """Return every policy violation in ``source`` (``allowed`` relaxes the filesystem group)."""
    forbidden = FORBIDDEN_MODULES - allowed
    tree = ast.parse(source)
    aliases = _module_aliases(tree)
    found: list[Violation] = []

    def add(node: ast.AST, detail: str) -> None:
        found.append(Violation(getattr(node, "lineno", 0), detail))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _root(alias.name) in forbidden:
                    add(node, f"import of forbidden module {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import of the project's own modules
                continue
            module = node.module or ""
            if _root(module) in forbidden:
                add(node, f"import from forbidden module {module}")
            for alias in node.names:
                if alias.name == "*":
                    add(node, f"star import from {module}")
                if (module, alias.name) in FORBIDDEN_MEMBERS:
                    add(node, f"import of forbidden member {module}.{alias.name}")
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_BUILTINS:
                add(node, f"use of forbidden builtin {node.id}")
        elif isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_DUNDER_ATTRIBUTES:
                add(node, f"access to forbidden attribute {node.attr}")
            if isinstance(node.value, ast.Name):
                module = aliases.get(node.value.id, node.value.id)
                if (module, node.attr) in FORBIDDEN_MEMBERS:
                    add(node, f"use of forbidden member {module}.{node.attr}")
    return found


FLAGGED_SNIPPETS = [
    "import socket",
    "import socket as s",
    "import urllib.request",
    "import urllib.request as ur",
    "from socket import socket as S",
    "from socket import *",
    "from urllib import request",
    "from urllib.request import urlopen as fetch",
    "from http.client import HTTPSConnection as Conn",
    "import requests",
    "import subprocess as sp",
    "from subprocess import run",
    "import importlib",
    "from importlib import import_module as im",
    "import runpy",
    "import ctypes as c",
    "import pickle",
    "import builtins as b",
    "import os",
    "import os.path as p",
    "from os import path as p",
    "import pathlib as pl",
    "from pathlib import Path",
    "import shutil",
    "import tempfile as t",
    "import sqlite3 as db",
    "import io",
    "import sys as s\nmodules = s.modules",
    "from sys import modules as m",
    "import yaml as y\ny.load('a: 1')",
    "from yaml import unsafe_load as ul",
    "eval('1')",
    "exec('x = 1')",
    "compile('1', 'f', 'eval')",
    "open('file.txt')",
    "__import__('socket')",
    "handler = open",
    "value = obj.__import__",
    "value = func.__globals__",
]
CLEAN_SNIPPETS = [
    "import argparse",
    "import argparse as ap",
    "import re",
    "import json",
    "import hashlib",
    "import dataclasses as dc",
    "from collections.abc import Sequence",
    "from dataclasses import dataclass",
    "from pydantic import BaseModel",
    "from soerm import __version__",
    "from . import sibling",
    "from .models import Thing",
    "import sys\nsys.stdout.write('x')",
    "import yaml\nyaml.safe_load('a: 1')",
    "opener = 1\nreopen = 2",
    "class Socket:\n    pass",
]


def _snippet_id(snippet: str) -> str:
    return snippet.replace("\n", "; ")


@pytest.mark.parametrize("source", FLAGGED_SNIPPETS, ids=_snippet_id)
def test_scanner_flags_forbidden_construct(source: str) -> None:
    assert find_violations(source), source


@pytest.mark.parametrize("source", CLEAN_SNIPPETS, ids=_snippet_id)
def test_scanner_accepts_allowed_construct(source: str) -> None:
    assert find_violations(source) == []


def test_production_code_has_no_forbidden_constructs() -> None:
    files = sorted(SRC_ROOT.rglob("*.py"))
    assert any(path.name == "main.py" for path in files), "source tree not found"
    problems = [
        f"{path.relative_to(PROJECT_ROOT)}:{violation.line}: {violation.detail}"
        for path in files
        for violation in find_violations(
            path.read_text(encoding="utf-8"),
            allowed_modules_for(path.relative_to(SRC_ROOT).as_posix()),
        )
    ]
    assert not problems, "\n".join(problems)


def test_allowances_only_relax_the_filesystem_group() -> None:
    granted = set().union(*MODULE_ALLOWANCES.values())
    assert granted <= FILESYSTEM_MODULES
    assert not granted & (NETWORK_MODULES | PROCESS_MODULES | DYNAMIC_CODE_MODULES)


@pytest.mark.parametrize(
    ("path", "module", "allowed"),
    [
        ("storage/connection.py", "sqlite3", True),
        ("storage/connection.py", "os", True),
        ("storage/lock.py", "fcntl", True),
        ("storage/audit.py", "sqlite3", True),
        ("storage/audit.py", "os", False),
        ("storage/audit.py", "fcntl", False),
        ("storage/migrations.py", "os", False),
        ("domain/asset.py", "sqlite3", False),
        ("domain/asset.py", "pathlib", False),
        ("cli/main.py", "os", False),
        ("cli/main.py", "pathlib", False),
        ("services/workspace.py", "pathlib", True),
        ("services/workspace.py", "sqlite3", False),
        ("services/assets.py", "pathlib", False),
        ("config/loader.py", "pathlib", True),
        ("config/loader.py", "os", True),
        ("config/loader.py", "sqlite3", False),
        ("importers/safe_file.py", "os", True),
        ("importers/safe_file.py", "pathlib", True),
        ("importers/sarif.py", "os", False),
        ("importers/sarif.py", "pathlib", False),
        ("importers/csv_import.py", "io", False),
        ("services/imports.py", "os", False),
        ("services/imports.py", "pathlib", False),
        ("config/schema.py", "os", False),
        ("services/redaction.py", "pathlib", True),
        ("domain/redaction.py", "os", False),
        ("tui/terminal.py", "os", True),
        ("tui/terminal.py", "pathlib", False),
        ("tui/app.py", "os", False),
        ("tui/data.py", "os", False),
        ("tui/data.py", "pathlib", False),
    ],
)
def test_allowances_apply_to_the_intended_files_only(path: str, module: str, allowed: bool) -> None:
    violations = find_violations(f"import {module}", allowed_modules_for(path))
    assert (not violations) is allowed


def _ruff_banned_api() -> dict[str, object]:
    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lint = config["tool"]["ruff"]["lint"]
    assert "TID" in lint["select"], "ruff TID rules must stay enabled"
    banned: dict[str, object] = lint["flake8-tidy-imports"]["banned-api"]
    return banned


def test_ruff_banned_api_is_covered_by_ast_policy() -> None:
    uncovered = []
    for key in _ruff_banned_api():
        module, _, member = key.partition(".")
        covered = (module, member) in FORBIDDEN_MEMBERS if member else module in FORBIDDEN_MODULES
        if not covered:
            uncovered.append(key)
    assert not uncovered, f"banned in ruff but not in the AST policy: {uncovered}"


def test_ast_policy_is_covered_by_ruff_banned_api() -> None:
    banned = set(_ruff_banned_api())
    expected = NETWORK_MODULES | PROCESS_MODULES | (DYNAMIC_CODE_MODULES - {"builtins"})
    missing = sorted(expected - banned)
    assert not missing, f"in the AST policy but not banned in ruff: {missing}"
