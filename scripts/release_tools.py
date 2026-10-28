"""Release tooling (not part of the wheel): wheel audit and a CycloneDX SBOM.

    python scripts/release_tools.py check-wheel dist/soerm-X-py3-none-any.whl
    python scripts/release_tools.py sbom --lock uv.lock --wheel dist/soerm-X-py3-none-any.whl \
        --output soerm.cdx.json

Both commands only read local files and never use the network. ``sbom`` is deterministic: no
timestamp, the serial number is derived from the content.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import sys
import tomllib
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Final

PROJECT: Final = "soerm"
ALLOWED_RUNTIME_REQUIRES: Final = frozenset({"pydantic", "pyyaml"})
ALLOWED_EXTRA_REQUIRES: Final = {"tui": frozenset({"textual"})}
FORBIDDEN_SUFFIXES: Final = (
    ".yaml", ".yml", ".sarif", ".csv", ".db", ".db-wal", ".db-shm", ".sqlite", ".lock",
    ".pem", ".key", ".env", ".pyc", ".pyo", ".so", ".dylib",
)  # fmt: skip
FORBIDDEN_DIRS: Final = ("tests", "examples", "scripts", "__pycache__", ".git")
SECRET_PATTERNS: Final = tuple(
    re.compile(pattern)
    for pattern in (
        r"://[^/\s:@]+:[^/\s@]+@",  # credentials inside a URL
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
        r"hunter2-TOP-SECRET-token",
        r"(?i)\b(?:https?_proxy|all_proxy)\s*=",
    )
)


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def check_wheel(path: Path) -> list[str]:
    """Return a list of problems (empty if the wheel is acceptable)."""
    problems: list[str] = []
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile):
        return ["wheel: unreadable"]
    with archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        if len(names) != len(set(names)):
            problems.append("wheel: duplicate member names")
        dist_info = sorted(
            {n.split("/")[0] for n in names if n.split("/")[0].endswith(".dist-info")}
        )
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts:
                problems.append(f"unsafe path: {name}")
                continue
            top = pure.parts[0]
            if top != PROJECT and not top.endswith(".dist-info"):
                problems.append(f"unexpected top-level entry: {name}")
            if any(part in FORBIDDEN_DIRS for part in pure.parts):
                problems.append(f"forbidden directory: {name}")
            if name.lower().endswith(FORBIDDEN_SUFFIXES):
                problems.append(f"forbidden file type: {name}")
        if len(dist_info) != 1:
            problems.append("wheel: expected exactly one .dist-info directory")
            return problems
        problems += _check_record(archive, names, dist_info[0])
        problems += _check_metadata(archive, dist_info[0])
        for name in names:
            if name.endswith(("/RECORD",)):
                continue
            data = archive.read(name)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                problems.append(f"non-text member: {name}")
                continue
            problems += [
                f"secret-like content in {name}"
                for pattern in SECRET_PATTERNS
                if pattern.search(text)
            ]
    return problems


def _check_record(archive: zipfile.ZipFile, names: list[str], dist_info: str) -> list[str]:
    problems: list[str] = []
    record_name = f"{dist_info}/RECORD"
    if record_name not in names:
        return ["RECORD: missing"]
    listed: dict[str, tuple[str, str]] = {}
    text = archive.read(record_name).decode("utf-8")
    for row in csv.reader(io.StringIO(text)):
        if len(row) != 3:
            problems.append("RECORD: malformed row")
            continue
        listed[row[0]] = (row[1], row[2])
    for name in names:
        if name == record_name:
            continue
        if name not in listed:
            problems.append(f"RECORD: not listed: {name}")
            continue
        digest, size = listed[name]
        data = archive.read(name)
        if digest != _record_hash(data) or (size and int(size) != len(data)):
            problems.append(f"RECORD: hash or size mismatch: {name}")
    problems += [
        f"RECORD: lists a missing file: {n}" for n in listed if n not in names and n != record_name
    ]
    return problems


def _check_metadata(archive: zipfile.ZipFile, dist_info: str) -> list[str]:
    problems: list[str] = []
    text = archive.read(f"{dist_info}/METADATA").decode("utf-8")
    requires_python = re.search(r"^Requires-Python:\s*(.+)$", text, re.MULTILINE)
    if requires_python is None or requires_python.group(1).strip() != ">=3.12":
        problems.append("METADATA: Requires-Python must be >=3.12")
    for line in re.findall(r"^Requires-Dist:\s*(.+)$", text, re.MULTILINE):
        name = re.match(r"[A-Za-z0-9_.-]+", line)
        extra = re.search(r"extra\s*==\s*['\"]([A-Za-z0-9_.-]+)['\"]", line)
        allowed = (
            ALLOWED_EXTRA_REQUIRES.get(extra.group(1), frozenset())
            if extra
            else ALLOWED_RUNTIME_REQUIRES
        )
        if name is None or name.group(0).lower() not in allowed:
            problems.append("METADATA: unexpected dependency")
    if "Private :: Do Not Upload" not in text:
        problems.append("METADATA: missing 'Private :: Do Not Upload'")
    return problems


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def dependency_graph(lock: dict[str, Any], extras: tuple[str, ...] = ()) -> dict[str, list[str]]:
    """Normalized name -> names it depends on, for SOERM and everything it needs at run time.

    ``extras`` adds SOERM's optional extras (for example ``tui``); extras that a locked package
    requests of another package (``markdown-it-py[linkify]``) are followed as well.
    """
    packages = {_normalize(p["name"]): p for p in lock["package"]}
    wanted: dict[str, set[str]] = {}
    graph: dict[str, list[str]] = {}
    todo: list[tuple[str, tuple[str, ...]]] = [(PROJECT, tuple(extras))]
    while todo:
        name, requested = todo.pop()
        known = wanted.setdefault(name, set())
        if name in graph and set(requested) <= known:
            continue
        known |= set(requested)
        package = packages[name]
        edges = list(package.get("dependencies", []))
        optional = package.get("optional-dependencies", {})
        for extra in sorted(known):
            edges += optional.get(extra, [])
        graph[name] = sorted({_normalize(d["name"]) for d in edges})
        todo += [(_normalize(d["name"]), tuple(d.get("extra", []))) for d in edges]
    return graph


def runtime_closure(lock: dict[str, Any], extras: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Locked packages SOERM needs at run time (its dependencies, transitively)."""
    packages = {_normalize(p["name"]): p for p in lock["package"]}
    return [packages[name] for name in sorted(dependency_graph(lock, extras)) if name != PROJECT]


def build_sbom(
    lock_text: str, wheel_bytes: bytes, wheel_name: str, version: str, extras: tuple[str, ...] = ()
) -> dict[str, Any]:
    lock = tomllib.loads(lock_text)
    components: list[dict[str, Any]] = []
    refs: dict[str, str] = {}
    for package in runtime_closure(lock, extras):
        name, ver = package["name"], package["version"]
        ref = f"pkg:pypi/{_normalize(name)}@{ver}"
        refs[_normalize(name)] = ref
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": ver,
            "purl": ref,
            "scope": "required",
        }
        sdist = package.get("sdist", {}).get("hash", "")
        if sdist.startswith("sha256:"):
            component["hashes"] = [{"alg": "SHA-256", "content": sdist.removeprefix("sha256:")}]
        components.append(component)
    root_ref = f"pkg:pypi/{PROJECT}@{version}"
    graph = dependency_graph(lock, extras)
    dependencies = [
        {"ref": root_ref, "dependsOn": sorted(refs[name] for name in graph[PROJECT])},
        *(
            {"ref": refs[name], "dependsOn": sorted(refs[dep] for dep in graph[name])}
            for name in sorted(graph)
            if name != PROJECT
        ),
    ]
    body: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": PROJECT,
                "version": version,
                "purl": root_ref,
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(wheel_bytes).hexdigest()}],
                "properties": [{"name": "soerm:artifact", "value": wheel_name}],
            },
            "properties": [
                {"name": "soerm:scope", "value": "runtime dependencies from uv.lock"},
                {"name": "soerm:extras", "value": ",".join(extras) or "none"},
                {
                    "name": "soerm:lock-sha256",
                    "value": hashlib.sha256(lock_text.encode()).hexdigest(),
                },
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {
        "bomFormat": body["bomFormat"],
        "specVersion": body["specVersion"],
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, digest)}",
        **{k: v for k, v in body.items() if k not in {"bomFormat", "specVersion"}},
    }


def _version_of(wheel: Path) -> str:
    match = re.fullmatch(rf"{PROJECT}-([^-]+)-.*\.whl", wheel.name)
    if match is None:
        raise SystemExit("wheel file name is not <name>-<version>-....whl")
    return match.group(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check-wheel")
    check.add_argument("wheel", type=Path)
    sbom = commands.add_parser("sbom")
    sbom.add_argument("--lock", type=Path, required=True)
    sbom.add_argument("--wheel", type=Path, required=True)
    sbom.add_argument("--output", type=Path, required=True)
    sbom.add_argument("--extra", action="append", default=[], help="include an optional extra")
    args = parser.parse_args(argv)
    if args.command == "check-wheel":
        problems = check_wheel(args.wheel)
        for problem in problems:
            sys.stdout.write(f"PROBLEM: {problem}\n")
        sys.stdout.write("wheel ok\n" if not problems else f"{len(problems)} problem(s)\n")
        return 1 if problems else 0
    document = build_sbom(
        args.lock.read_text(encoding="utf-8"),
        args.wheel.read_bytes(),
        args.wheel.name,
        _version_of(args.wheel),
        tuple(args.extra),
    )
    text = json.dumps(document, indent=2) + "\n"
    args.output.write_text(text, encoding="utf-8")
    sys.stdout.write(f"sbom written: {args.output} ({len(document['components'])} components)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
