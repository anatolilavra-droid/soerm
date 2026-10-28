"""Release tooling: wheel audit, SBOM content, and the project's own shipped text."""

import base64
import hashlib
import importlib.util
import json
import re
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from tests.unit.storage.conftest import PROJECT_ROOT

SPEC = importlib.util.spec_from_file_location(
    "release_tools", PROJECT_ROOT / "scripts" / "release_tools.py"
)
assert SPEC is not None
assert SPEC.loader is not None
tools: ModuleType = importlib.util.module_from_spec(SPEC)
import sys  # noqa: E402

sys.modules["release_tools"] = tools
SPEC.loader.exec_module(tools)

METADATA = (
    "Metadata-Version: 2.4\nName: soerm\nVersion: 1.0\nRequires-Python: >=3.12\n"
    "Classifier: Private :: Do Not Upload\nRequires-Dist: pydantic>=2.6\n"
    "Requires-Dist: PyYAML>=6.0\n"
)
LOCK = """
version = 1
[[package]]
name = "soerm"
version = "1.0"
source = { editable = "." }
dependencies = [{ name = "pydantic" }, { name = "pyyaml" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }]
[[package]]
name = "pydantic"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "annotated-types" }]
sdist = { url = "https://files.pythonhosted.org/x.tar.gz", hash = "sha256:%s", size = 1 }
[[package]]
name = "annotated-types"
version = "0.1"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "pyyaml"
version = "6.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "pytest"
version = "9.0"
source = { registry = "https://pypi.org/simple" }
""" % ("a" * 64)


def record_row(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def make_wheel(
    path: Path,
    extra: dict[str, bytes] | None = None,
    *,
    metadata: str = METADATA,
    bad_record: bool = False,
) -> Path:
    members = {
        "soerm/__init__.py": b'"""soerm."""\n',
        "soerm-1.0.dist-info/METADATA": metadata.encode(),
        "soerm-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
    }
    members.update(extra or {})
    rows = [record_row(n, d) for n, d in members.items()]
    if bad_record:
        rows[0] = rows[0].replace("sha256=", "sha256=X")
    rows.append("soerm-1.0.dist-info/RECORD,,")
    members["soerm-1.0.dist-info/RECORD"] = ("\n".join(rows) + "\n").encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def test_clean_wheel_passes(tmp_path: Path) -> None:
    assert tools.check_wheel(make_wheel(tmp_path / "soerm-1.0-py3-none-any.whl")) == []


@pytest.mark.parametrize(
    "name",
    [
        "tests/test_x.py",
        "soerm/tests/test_x.py",
        "examples/soerm.yaml",
        "soerm/data/scan.sarif",
        "soerm/data/rows.csv",
        "soerm/soerm.db",
        "soerm/soerm.db-wal",
        "soerm/.soerm.lock",
        "soerm/__pycache__/x.pyc",
        "other/module.py",
    ],
)
def test_forbidden_members_are_reported(tmp_path: Path, name: str) -> None:
    wheel = make_wheel(tmp_path / "w.whl", {name: b"x = 1\n"})
    assert tools.check_wheel(wheel)


def test_record_mismatch_is_reported(tmp_path: Path) -> None:
    problems = tools.check_wheel(make_wheel(tmp_path / "w.whl", bad_record=True))
    assert any("RECORD" in p for p in problems)


def test_unlisted_file_is_reported(tmp_path: Path) -> None:
    wheel = make_wheel(tmp_path / "w.whl")
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("soerm/extra.py", b"x = 1\n")
    assert any("not listed" in p for p in tools.check_wheel(wheel))


@pytest.mark.parametrize(
    "secret",
    [
        "see https://user:pass@example.org/x",
        "-----BEGIN RSA PRIVATE KEY-----",
        "key AKIAABCDEFGHIJKLMNOP",
        "https_proxy=http://proxy:3128",
        "hunter2-TOP-SECRET-token",
    ],
)
def test_secret_like_content_is_reported(tmp_path: Path, secret: str) -> None:
    wheel = make_wheel(tmp_path / "w.whl", {"soerm/mod.py": f"# {secret}\n".encode()})
    assert any("secret-like" in p for p in tools.check_wheel(wheel))


def test_metadata_rules(tmp_path: Path) -> None:
    low = METADATA.replace(">=3.12", ">=3.9")
    assert tools.check_wheel(make_wheel(tmp_path / "a.whl", metadata=low))
    extra = METADATA + "Requires-Dist: requests>=2\n"
    assert tools.check_wheel(make_wheel(tmp_path / "b.whl", metadata=extra))
    public = METADATA.replace("Classifier: Private :: Do Not Upload\n", "")
    assert tools.check_wheel(make_wheel(tmp_path / "c.whl", metadata=public))


def test_unreadable_wheel(tmp_path: Path) -> None:
    broken = tmp_path / "w.whl"
    broken.write_bytes(b"not a zip")
    assert tools.check_wheel(broken) == ["wheel: unreadable"]


def test_sbom_is_cyclonedx_with_runtime_closure_only() -> None:
    document = tools.build_sbom(LOCK, b"wheel-bytes", "soerm-1.0-py3-none-any.whl", "1.0")
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["serialNumber"].startswith("urn:uuid:")
    names = [c["name"] for c in document["components"]]
    assert names == ["annotated-types", "pydantic", "pyyaml"]  # no pytest (dev only)
    pydantic = next(c for c in document["components"] if c["name"] == "pydantic")
    assert pydantic["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]
    assert pydantic["purl"] == "pkg:pypi/pydantic@2.0"
    root = document["metadata"]["component"]
    assert root["hashes"][0]["content"] == hashlib.sha256(b"wheel-bytes").hexdigest()
    graph = {d["ref"]: d["dependsOn"] for d in document["dependencies"]}
    assert graph["pkg:pypi/soerm@1.0"] == ["pkg:pypi/pydantic@2.0", "pkg:pypi/pyyaml@6.0"]
    assert graph["pkg:pypi/pydantic@2.0"] == ["pkg:pypi/annotated-types@0.1"]
    assert "timestamp" not in json.dumps(document)


def test_sbom_is_deterministic_and_secret_free() -> None:
    first = tools.build_sbom(LOCK, b"w", "soerm-1.0-py3-none-any.whl", "1.0")
    second = tools.build_sbom(LOCK, b"w", "soerm-1.0-py3-none-any.whl", "1.0")
    assert first == second
    text = json.dumps(first)
    assert not any(pattern.search(text) for pattern in tools.SECRET_PATTERNS)
    assert "/home/" not in text


def test_text_that_ships_in_the_wheel_holds_no_secret_like_content() -> None:
    for name in ("README.md", "pyproject.toml"):
        text = (PROJECT_ROOT / name).read_text(encoding="utf-8")
        for pattern in tools.SECRET_PATTERNS:
            assert not pattern.search(text), (name, pattern.pattern)


def test_lock_file_uses_only_the_default_registry_and_pins_hashes() -> None:
    text = (PROJECT_ROOT / "uv.lock").read_text(encoding="utf-8")
    assert set(re.findall(r'registry = "([^"]+)"', text)) == {"https://pypi.org/simple"}
    hosts = set(re.findall(r'url = "https?://([^/"]+)', text))
    assert hosts == {"files.pythonhosted.org"}
    assert "@" not in "".join(re.findall(r'url = "[^"]+"', text))  # no credentials in URLs
    urls = len(re.findall(r'url = "', text))
    hashes = len(re.findall(r'hash = "sha256:[0-9a-f]{64}"', text))
    assert hashes == urls > 0


REQUIRED_README_TOPICS = (
    "Назначение",
    "Python 3.12",
    "uv sync",
    "Сквозной сценарий",
    "Модель безопасности",
    "Shell history",
    "Блокировка POSIX",
    "Audit без внешнего якоря",
    "TOCTOU",
    "Поддерживаемые подмножества импорта",
    "Миграции и совместимость",
    "Резервные копии и восстановление",
    "Нет сетевого доступа",
    "check-wheel",
    "CycloneDX",
    "Release checklist",
    "M12",
)


@pytest.mark.parametrize("topic", REQUIRED_README_TOPICS)
def test_readme_documents_the_release_topics(topic: str) -> None:
    text = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert topic in text


LOCK_WITH_EXTRA = (
    LOCK.replace(
        'dependencies = [{ name = "pydantic" }, { name = "pyyaml" }]',
        'dependencies = [{ name = "pydantic" }, { name = "pyyaml" }]\n'
        "[package.optional-dependencies]\n"
        'tui = [{ name = "textual" }]',
    )
    + """
[[package]]
name = "textual"
version = "8.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "markdown-it-py", extra = ["linkify"] }]
[[package]]
name = "markdown-it-py"
version = "4.0"
source = { registry = "https://pypi.org/simple" }
[package.optional-dependencies]
linkify = [{ name = "linkify-it-py" }]
[[package]]
name = "linkify-it-py"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
"""
)


def test_sbom_with_an_extra_follows_extras_of_dependencies() -> None:
    base = tools.build_sbom(LOCK_WITH_EXTRA, b"w", "soerm-1.0-py3-none-any.whl", "1.0")
    full = tools.build_sbom(LOCK_WITH_EXTRA, b"w", "soerm-1.0-py3-none-any.whl", "1.0", ("tui",))
    assert [c["name"] for c in base["components"]] == ["annotated-types", "pydantic", "pyyaml"]
    names = [c["name"] for c in full["components"]]
    assert names == [
        "annotated-types", "linkify-it-py", "markdown-it-py", "pydantic", "pyyaml", "textual",
    ]  # fmt: skip
    graph = {d["ref"]: d["dependsOn"] for d in full["dependencies"]}
    assert "pkg:pypi/textual@8.0" in graph["pkg:pypi/soerm@1.0"]
    assert graph["pkg:pypi/markdown-it-py@4.0"] == ["pkg:pypi/linkify-it-py@2.0"]
    assert {"name": "soerm:extras", "value": "tui"} in full["metadata"]["properties"]


def test_optional_extra_requirement_is_accepted_but_others_are_not(tmp_path: Path) -> None:
    allowed = METADATA + "Provides-Extra: tui\nRequires-Dist: textual>=8; extra == 'tui'\n"
    assert tools.check_wheel(make_wheel(tmp_path / "a.whl", metadata=allowed)) == []
    other = METADATA + "Requires-Dist: requests>=2; extra == 'tui'\n"
    assert tools.check_wheel(make_wheel(tmp_path / "b.whl", metadata=other))
    unknown = METADATA + "Requires-Dist: textual>=8; extra == 'other'\n"
    assert tools.check_wheel(make_wheel(tmp_path / "c.whl", metadata=unknown))
