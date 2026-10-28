"""Shared pytest configuration.

The autouse ``network_guard`` fixture makes any attempt to use the network fail the test.
Every blocked call is also recorded, so a test still fails at teardown if the code under
test swallowed the resulting exception.
"""

import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, NoReturn

import pytest

GUARDED_SOCKET_METHODS: tuple[str, ...] = ("connect", "connect_ex", "sendto", "bind", "listen")
GUARDED_SOCKET_FUNCTIONS: tuple[str, ...] = (
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
)


@dataclass
class NetworkGuard:
    """Record of blocked network calls made during one test."""

    blocked: tuple[str, ...] = ()
    attempts: list[str] = field(default_factory=list)

    def acknowledge(self) -> None:
        """Declare recorded attempts as expected (used only by the guard's own tests)."""
        self.attempts.clear()

    def verify(self) -> None:
        """Fail if any blocked call was made and not acknowledged."""
        assert not self.attempts, f"unacknowledged network attempts: {self.attempts}"


def _blocked_callable(qualified_name: str, guard: NetworkGuard) -> Callable[..., NoReturn]:
    def blocked(*_args: Any, **_kwargs: Any) -> NoReturn:
        guard.attempts.append(qualified_name)
        pytest.fail(f"network access is blocked in tests: {qualified_name}", pytrace=False)

    blocked.__name__ = "blocked_" + qualified_name.replace(".", "_")
    return blocked


@pytest.fixture(autouse=True)
def network_guard(monkeypatch: pytest.MonkeyPatch) -> Iterator[NetworkGuard]:
    """Block outgoing network access for every test."""
    targets: list[tuple[object, str, str]] = []
    targets.extend((socket.socket, name, f"socket.{name}") for name in GUARDED_SOCKET_METHODS)
    targets.extend((socket, name, f"socket.{name}") for name in GUARDED_SOCKET_FUNCTIONS)

    guard = NetworkGuard(blocked=tuple(qualified for _, _, qualified in targets))
    originals = [(target, name, getattr(target, name)) for target, name, _ in targets]
    for target, name, qualified in targets:
        monkeypatch.setattr(target, name, _blocked_callable(qualified, guard))

    yield guard

    monkeypatch.undo()
    for target, name, original in originals:
        assert getattr(target, name) is original, f"network guard did not restore {name}"
    guard.verify()
