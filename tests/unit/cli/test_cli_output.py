"""Output safety: no ANSI, no control characters, deterministic JSON."""
# (look-alike and bidirectional characters are deliberate test data)

import json
from pathlib import Path

import pytest

from soerm.cli.output import dumps_json, render_key_values, render_table, safe_text, write_line
from tests.unit.cli.conftest import Runner, add_asset, add_finding, assert_terminal_safe
from tests.unit.services.helpers import SECRET

HOSTILE = "\x1b[31mred\x1b[0m\x07\x08\x00\x7f\u202e\u200b\u2028\ufeff\ud800\ue000\u0378\u00a0\t\r\n"


def test_safe_text_removes_every_unsafe_character() -> None:
    cleaned = safe_text(HOSTILE)
    assert_terminal_safe(cleaned)
    assert "\n" not in cleaned
    assert "\\x1b" not in cleaned  # escapes use \uXXXX
    assert "\\u001b" in cleaned
    assert "\\u202e" in cleaned
    assert "\\ue000" in cleaned
    assert "\\ud800" in cleaned
    assert "\\n" in cleaned


def test_safe_text_leaves_ordinary_text_alone() -> None:
    assert (
        safe_text("Billing API: v2 (prod) — «тест» 日本語")
        == "Billing API: v2 (prod) — «тест» 日本語"
    )


def test_safe_text_escapes_astral_private_use() -> None:
    assert safe_text("\U000f0000") == "\\U000f0000"


def test_limit_shortens_with_an_ellipsis() -> None:
    assert safe_text("x" * 100, limit=10) == "xxxxxxx..."
    assert safe_text("short", limit=10) == "short"


def test_key_values_and_table_are_aligned_and_safe() -> None:
    text = render_key_values([("a", "1"), ("longer", HOSTILE)])
    assert_terminal_safe(text)
    assert text.splitlines()[0].startswith("a:      ")
    table = render_table(("ID", "TITLE"), [("1", HOSTILE), ("22", "x" * 200)], limit=20)
    assert_terminal_safe(table)
    assert all(len(line) <= 40 for line in table.splitlines())


def test_json_is_ascii_and_keeps_the_given_order() -> None:
    text = dumps_json({"z": 1, "a": HOSTILE, "m": ["\x1b", "тест"]})
    assert text.isascii()
    assert "\x1b" not in text
    assert list(json.loads(text)) == ["z", "a", "m"]
    assert json.loads(text)["m"] == ["\x1b", "тест"]


def test_json_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError, match="Out of range"):
        dumps_json({"x": float("nan")})


def test_write_line_survives_streams_that_cannot_encode(capsys: pytest.CaptureFixture[str]) -> None:
    import io

    buffer = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    write_line("тест ✓", buffer)
    buffer.seek(0)
    assert buffer.read() == "\\u0442\\u0435\\u0441\\u0442 \\u2713\n"
    capsys.readouterr()


def test_unusual_but_valid_characters_are_escaped_in_the_terminal_views(
    cli: Runner, workspace: Path
) -> None:
    weird = "ab\ue000\u0378cd"
    assert (
        cli("asset", "add", "--workspace", str(workspace), "--actor", "a", "--name", weird,
            "--owner", weird, "--environment", "test", "--criticality", "low",
            "--classification", "public", "--exposure", "isolated", "--tag", weird).code == 0
    )  # fmt: skip
    for argv in (
        ("asset", "show", "AST-000001"),
        ("asset", "list"),
        ("asset", "list", "--json"),
        ("asset", "show", "AST-000001", "--json"),
    ):
        result = cli(*argv[:2], "--workspace", str(workspace), *argv[2:])
        assert result.code == 0
        assert_terminal_safe(result.out)
        assert "\\ue000" in result.out or "\\ue000" in json.dumps(json.loads(result.out))


def test_hostile_title_and_description_in_every_view(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    result = add_finding(
        cli, workspace, "--description", HOSTILE.replace("\ud800", ""), "--owner", "o\x1b[2Jo"
    )
    assert result.code == 0
    ws = str(workspace)
    for argv in (
        ("finding", "show", "--workspace", ws, "FND-000001"),
        ("finding", "show", "--workspace", ws, "FND-000001", "--json"),
        ("finding", "list", "--workspace", ws),
        ("finding", "list", "--workspace", ws, "--json"),
    ):
        shown = cli(*argv)
        assert shown.code == 0
        assert_terminal_safe(shown.out)
        assert "\x1b" not in shown.out


def test_errors_are_terminal_safe(cli: Runner, workspace: Path) -> None:
    result = cli("asset", "show", "--workspace", str(workspace), "\x1b[31m" + SECRET)
    assert result.code == 1
    assert_terminal_safe(result.err)
    assert SECRET not in result.err
