"""명세 2절 — 바꿔 끼울 수 있는 포트. SDK 안에서 시계 · 타이머 · 난수를 직접 읽지 않는다.

이름은 명세의 Transport · CredentialStore · Clock · Scheduler · Random · FingerprintSource · Logger이고, `random` · `logging`과 헷갈리지 않게 Swift ·
Kotlin SDK와 같은 이름으로 바꿨다.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class HttpRequest:
    """전송 포트가 보낼 요청이다. `body`가 None이면 본문이 없다. 헤더 이름은 소문자다."""

    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None


@dataclass(frozen=True)
class HttpResponse:
    """받은 응답이다. 헤더 이름은 소문자다."""

    status: int
    headers: dict[str, str]
    body: bytes


class HttpTransport(Protocol):
    """요청을 보낸다. 연결 실패 · 시간 초과는 던진다(SDK가 `NETWORK_ERROR`로 감싼다). 3xx를 따라가지 않는다."""

    def send(self, request: HttpRequest) -> HttpResponse: ...


@dataclass(frozen=True)
class CredentialRecord:
    """보안 저장소에 두는 기록이다(명세 3.6). access_token은 두지 않는다."""

    version: int
    refresh_token: str
    scope: str
    saved_at: str


class CredentialStore(Protocol):
    """로그인 기록을 둔다. 없으면 `load`가 None. 실패는 던진다(SDK가 `STORAGE_FAILED`로 감싼다)."""

    def load(self) -> CredentialRecord | None: ...

    def save(self, record: CredentialRecord) -> None: ...

    def clear(self) -> None: ...


class WallClock(Protocol):
    """지금 시각(Unix 밀리초) — 명세의 Clock."""

    def now_ms(self) -> int: ...


class Cancel:
    """예약 취소 손잡이. 놓아도 취소하지 않는다 — `cancel()`을 부른다."""

    def __init__(self, on_cancel: Callable[[], None]) -> None:
        self._on_cancel = on_cancel
        self._done = False
        self._lock = threading.Lock()

    def cancel(self) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        self._on_cancel()


class Signal:
    """한 번 켜지는 신호 — 다른 작업의 끝(single-flight · 로그인)을 기다릴 때 쓴다. SDK는 `block()`을 직접 부르지 않고 `TaskScheduler.wait`를 거친다."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def fire(self) -> None:
        self._event.set()

    @property
    def is_fired(self) -> bool:
        return self._event.is_set()

    def block(self, timeout: float | None = None) -> bool:
        """켜질 때까지(또는 `timeout`초까지) 막는다. 켜졌으면 True."""
        return self._event.wait(timeout)


class TaskScheduler(Protocol):
    """나중 작업 · 기다림 — 명세의 Scheduler. SDK가 시간이나 다른 작업을 기다리는 곳은 모두 `sleep` · `wait`를 거친다(명세 2절 — 블로킹 언어).

    SDK는 스스로 스레드를 만들지 않고 `after`로만 백그라운드 작업을 시작한다.
    """

    def after(self, delay_ms: int, task: Callable[[], None]) -> Cancel: ...

    def sleep(self, ms: int) -> None: ...

    def wait(self, signal: Signal) -> None: ...


class RandomSource(Protocol):
    """`[0, 1)` 실수와 UUID v4(소문자) — 명세의 Random."""

    def random(self) -> float: ...

    def uuid(self) -> str: ...


class FingerprintSource(Protocol):
    """운영체제의 기기 식별자다. 없으면 None — 원본은 SDK 밖으로 나가지 않는다(해시만, 명세 10절)."""

    def read(self) -> str | None: ...


class LogSink(Protocol):
    """토큰 · 지문 출처 값은 넘어오지 않는다 — 명세의 Logger."""

    def debug(self, message: str) -> None: ...

    def info(self, message: str) -> None: ...

    def warn(self, message: str) -> None: ...


@dataclass
class Ports:
    """클라이언트가 쓰는 포트 묶음이다. 비운 칸은 기본 구현이다."""

    transport: HttpTransport | None = None
    store: CredentialStore | None = None
    clock: WallClock | None = None
    scheduler: TaskScheduler | None = None
    random: RandomSource | None = None
    fingerprint: FingerprintSource | None = None
    logger: LogSink | None = None


@dataclass(frozen=True)
class ResolvedPorts:
    """기본값을 채운 포트."""

    transport: HttpTransport
    store: CredentialStore
    clock: WallClock
    scheduler: TaskScheduler
    random: RandomSource
    fingerprint: FingerprintSource
    logger: LogSink


def resolve(ports: Ports) -> ResolvedPorts:
    from .defaults import (
        MemoryCredentialStore,
        NoFingerprint,
        SecureRandom,
        SilentLog,
        SystemClock,
        ThreadScheduler,
        UrllibTransport,
    )

    # 빈 칸(None)만 기본값으로 채운다 — `or`로 고르면 앱이 준 포트가 거짓으로 판정될 때(__len__ 0 등) 말없이 바뀌어 로그인 기록이 사라진다
    return ResolvedPorts(
        transport=ports.transport if ports.transport is not None else UrllibTransport(),
        store=ports.store if ports.store is not None else MemoryCredentialStore(),
        clock=ports.clock if ports.clock is not None else SystemClock(),
        scheduler=ports.scheduler if ports.scheduler is not None else ThreadScheduler(),
        random=ports.random if ports.random is not None else SecureRandom(),
        fingerprint=ports.fingerprint if ports.fingerprint is not None else NoFingerprint(),
        logger=ports.logger if ports.logger is not None else SilentLog(),
    )
