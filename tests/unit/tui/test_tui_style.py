"""The shared look: badges carry a glyph and a word (never colour alone), times are short."""

import pytest

from soerm.tui import style


@pytest.mark.parametrize(
    ("column", "value", "plain", "colour"),
    [
        ("Severity", "critical", "✖ CRITICAL", style.CRIT),
        ("Severity", "high", "▲ HIGH", style.CRIT),
        ("Severity", "medium", "◆ MEDIUM", style.WARN),
        ("Severity", "low", "▽ LOW", style.ACTIVE),
        ("Prio", "p1", "✖ P1", style.CRIT),
        ("priority", "p2", "▲ P2", style.WARN),
        ("Status", "pending", "◌ pending", style.WARN),
        ("Status", "in_progress", "◐ in progress", style.ACTIVE),
        ("Status", "approved", "✔ approved", style.OK),
        ("Status", "expired", "✖ expired", style.CRIT),
        ("Status", "intact", "✔ intact", style.OK),
        ("Status", "broken", "✖ broken", style.CRIT),
        ("Exposure", "internet", "▲ internet", style.WARN),
        ("Applied", "yes", "✔ yes", style.OK),
    ],
)
def test_badges_have_glyph_word_and_role_colour(
    column: str, value: str, plain: str, colour: str
) -> None:
    badge = style.badge(column, value)
    assert badge is not None
    assert badge.plain == plain
    assert colour in str(badge.style)


def test_every_badge_is_readable_without_colour() -> None:
    for table in (style._SEVERITY, style._PRIORITY, style._STATUS, style._EXPOSURE, style._YES_NO):
        for value, (glyph, _) in table.items():
            assert glyph.strip(), value
            assert glyph not in {"", " "}


def test_unknown_columns_and_values_are_not_badged() -> None:
    assert style.badge("Title", "high") is None
    assert style.badge("Severity", "surprising") is None


def test_cell_uses_muted_dash_short_time_and_plain_text() -> None:
    assert style.cell("Owner", "-").style == style.MUTED
    assert style.cell("SLA due", "2026-10-31T16:15:04.628082Z").plain == "2026-10-31 16:15Z"
    assert style.cell("Title", "Weak TLS").plain == "Weak TLS"
    assert style.cell("Status", "open").plain == "● open"


def test_stamp_formats_only_iso_times() -> None:
    value = "2026-10-31T16:15:04.628082Z"
    assert style.stamp(value) == "2026-10-31 16:15Z"
    assert style.stamp(value, seconds=True) == "2026-10-31 16:15:04Z"
    for other in ("-", "hello", "2026-10-31", "T" * 30, ""):
        assert style.stamp(other) == other


def test_big_number_is_three_lines_and_clamped() -> None:
    lines = style.big_number(2026, style.ACTIVE).plain.splitlines()
    assert len(lines) == 3
    assert len({len(line) for line in lines}) == 1
    assert style.big_number(-5, style.ACTIVE).plain == style.big_number(0, style.ACTIVE).plain


def test_key_values_mutes_labels_and_badges_status_rows() -> None:
    text = style.key_values(
        [("status", "open"), ("owner", "-"), ("sla due", "2026-10-31T16:15:04Z")]
    )
    assert "● open" in text.plain
    assert "2026-10-31 16:15:04Z" in text.plain
    assert text.plain.splitlines()[1].startswith("owner")


def test_palette_roles_are_distinct() -> None:
    roles = {style.ACTIVE, style.ACCENT, style.WARN, style.CRIT, style.OK}
    assert len(roles) == 5


def test_long_values_wrap_under_the_value_column() -> None:
    long = "step-004 [manual] Block the sender domain (approval required)"
    lines = style.key_values([("step 4", long)], width=18, wrap_at=48).plain.splitlines()
    assert len(lines) >= 2
    assert all(len(line) <= 48 for line in lines)
    assert all(line.startswith(" " * 18) for line in lines[1:])
    assert style.key_values([("step 4", long)]).plain.count("\n") == 1  # no width: one line
