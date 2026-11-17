"""안쪽 도우미 — 응답 읽기 · single-flight · 반올림 · 시각 · 인코딩."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Generic, TypeVar

from ._generated import Codes
from .errors import BydevError
from .ports import RandomSource, Signal, TaskScheduler

T = TypeVar("T")


def dumps(value: Any) -> str:
    """간결한 JSON — 객체 키는 이름순, 한글을 `\\uXXXX`로 바꾸지 않는다(다른 SDK와 같은 모양)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def loads(data: bytes | str) -> Any:
    """JSON이 아니면 None — 엄격하게(NaN · Infinity 거부)."""

    def reject(token: str) -> Any:
        raise ValueError(token)

    try:
        return json.loads(data, parse_constant=reject)
    except (ValueError, UnicodeDecodeError):
        return None


def _is_int(v: Any) -> bool:
    return (isinstance(v, int) and not isinstance(v, bool)) or (
        isinstance(v, float) and v.is_integer() and abs(v) < 9e15
    )


class Reader:
    """응답 읽기(명세 3.2) — 처음 어긋난 곳을 `PROTOCOL_ERROR`로 기억하고 기본값으로 이어 읽는다. 모르는 필드는 버린다."""

    _MISSING: Any = object()

    def __init__(self) -> None:
        self.error: BydevError | None = None

    def _fail(self, path: str, want: str, got: Any) -> None:
        if self.error is not None:
            return
        message = (
            f"응답에 {path}가 없다"
            if got is self._MISSING
            else f"응답의 {path}가 {want}가 아니다 ({dumps(got)})"
        )
        self.error = BydevError(Codes.PROTOCOL_ERROR, message)

    def get(self, obj: dict[str, Any], key: str) -> Any:
        return obj.get(key, self._MISSING)

    def obj(self, v: Any, path: str) -> dict[str, Any]:
        if isinstance(v, dict):
            return v
        self._fail(path, "객체", v)
        return {}

    def text(self, v: Any, path: str) -> str:
        if isinstance(v, str):
            return v
        self._fail(path, "문자열", v)
        return ""

    def integer(self, v: Any, path: str) -> int:
        if _is_int(v):
            return int(v)
        self._fail(path, "정수", v)
        return 0

    def flag(self, v: Any, path: str) -> bool:
        if isinstance(v, bool):
            return v
        self._fail(path, "참/거짓", v)
        return False

    def items(self, v: Any, path: str) -> list[Any]:
        if isinstance(v, list):
            return v
        self._fail(path, "배열", v)
        return []

    def opt_text(self, v: Any, path: str) -> str | None:
        return None if v is None or v is self._MISSING else self.text(v, path)

    def opt_integer(self, v: Any, path: str) -> int | None:
        return None if v is None or v is self._MISSING else self.integer(v, path)

    def finish(self, value: T) -> T:
        if self.error is not None:
            raise self.error
        return value


class _Flight(Generic[T]):
    def __init__(self) -> None:
        self.done = Signal()
        self.value: T | None = None
        self.error: BaseException | None = None
        self.ok = False


class SingleFlight(Generic[T]):
    """한 번에 하나만 도는 작업이다 — 기다리는 쪽은 `TaskScheduler.wait`로 기다린다(명세 2절 · 6절 1)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current: _Flight[T] | None = None

    def run(self, scheduler: TaskScheduler, work: Callable[[], T]) -> T:
        with self._lock:
            running = self._current
            if running is None:
                flight: _Flight[T] = _Flight()
                self._current = flight
        if running is not None:
            scheduler.wait(running.done)
            if running.error is not None:
                raise running.error
            if not running.ok:
                raise BydevError(Codes.PROTOCOL_ERROR, "작업 결과가 없다")
            return running.value  # type: ignore[return-value]
        try:
            value = work()
            flight.value, flight.ok = value, True
            return value
        except BaseException as e:
            flight.error = e
            raise
        finally:
            with self._lock:
                self._current = None
            flight.done.fire()


def rounded_ms(x: float) -> int:
    """`floor(x + 0.5)` 밀리초 — 명세 2절의 반올림."""
    return math.floor(x + 0.5)


def seconds(sec: float) -> int:
    """초(소수 가능) → 밀리초."""
    return rounded_ms(sec * 1000)


def jittered(random: RandomSource, base_ms: int, lo: float, hi: float) -> int:
    """`round(base × (min + (max − min) × r))`."""
    return rounded_ms(base_ms * (lo + (hi - lo) * random.random()))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url(text: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def format_iso(ms: int) -> str:
    """UTC ISO 8601 — 밀리초가 0이면 뗀다(`2026-10-06T13:00:00Z` · `…:00.250Z`)."""
    sec, millis = divmod(ms, 1000)
    base = datetime.fromtimestamp(sec, UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}Z" if millis == 0 else f"{base}.{millis:03d}Z"


def parse_iso(text: str) -> int | None:
    """RFC 3339(`Z` 또는 `±hh:mm`, 소수 초 허용) → Unix 밀리초. 읽지 못하면 None."""
    if len(text) < 20 or text[10] not in "Tt":
        return None
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text[-1] in "Zz" else text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return (parsed - _EPOCH) // timedelta(milliseconds=1)


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
