"""Meta-tests: the autouse network guard must really block network access."""

import contextlib
import socket
from collections.abc import Callable
from contextlib import closing
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.conftest import NetworkGuard

ADDRESS = ("127.0.0.1", 9)


def _new_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def _connect() -> None:
    with closing(_new_socket()) as sock:
        sock.connect(ADDRESS)


def _connect_ex() -> None:
    with closing(_new_socket()) as sock:
        sock.connect_ex(ADDRESS)


def _sendto() -> None:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.sendto(b"x", ADDRESS)


def _bind() -> None:
    with closing(_new_socket()) as sock:
        sock.bind(("127.0.0.1", 0))


def _listen() -> None:
    with closing(_new_socket()) as sock:
        sock.listen(1)


BLOCKED_CALLS: dict[str, Callable[[], object]] = {
    "socket.connect": _connect,
    "socket.connect_ex": _connect_ex,
    "socket.sendto": _sendto,
    "socket.bind": _bind,
    "socket.listen": _listen,
    "socket.create_connection": lambda: socket.create_connection(ADDRESS),
    "socket.create_server": lambda: socket.create_server(("127.0.0.1", 0)),
    "socket.getaddrinfo": lambda: socket.getaddrinfo("example.invalid", 80),
    "socket.gethostbyname": lambda: socket.gethostbyname("example.invalid"),
    "socket.gethostbyname_ex": lambda: socket.gethostbyname_ex("example.invalid"),
    "socket.gethostbyaddr": lambda: socket.gethostbyaddr("127.0.0.1"),
}


@pytest.mark.parametrize("name", sorted(BLOCKED_CALLS))
def test_blocked_call_fails_and_is_recorded(name: str, network_guard: "NetworkGuard") -> None:
    with pytest.raises(pytest.fail.Exception, match="network access is blocked"):
        BLOCKED_CALLS[name]()
    assert network_guard.attempts == [name]
    network_guard.acknowledge()


def test_every_guarded_name_has_a_meta_test(network_guard: "NetworkGuard") -> None:
    assert set(BLOCKED_CALLS) == set(network_guard.blocked)


def test_guard_is_installed_without_requesting_it() -> None:
    assert socket.getaddrinfo.__name__.startswith("blocked_")
    assert socket.create_connection.__name__.startswith("blocked_")
    assert socket.socket.connect.__name__.startswith("blocked_")


def test_swallowed_block_is_still_recorded_and_would_fail_teardown(
    network_guard: "NetworkGuard",
) -> None:
    with contextlib.suppress(BaseException):
        socket.getaddrinfo("example.invalid", 80)
    assert network_guard.attempts == ["socket.getaddrinfo"]
    with pytest.raises(AssertionError, match="unacknowledged"):
        network_guard.verify()
    network_guard.acknowledge()


def test_verify_passes_only_after_acknowledge(network_guard: "NetworkGuard") -> None:
    fresh = type(network_guard)()
    fresh.verify()
    fresh.attempts.append("socket.connect")
    with pytest.raises(AssertionError, match="unacknowledged"):
        fresh.verify()
    fresh.acknowledge()
    fresh.verify()
