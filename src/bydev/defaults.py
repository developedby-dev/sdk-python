"""명세 2절 — 기본 구현. 운영체제 저장소 · 지문 출처는 앱이 고른다(`bydev.platform`)."""

from __future__ import annotations

import secrets
import threading
import time
import urllib.error
import urllib.request
import uuid as _uuid
from collections.abc import Callable
from typing import Any

from ._generated import Codes, Rules
from .errors import BydevError
from .ports import Cancel, CredentialRecord, HttpRequest, HttpResponse, Signal


class SystemClock:
    """시스템 시계 — SDK에서 시계를 직접 읽는 유일한 곳."""

    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


class ThreadScheduler:
    """데몬 스레드 스케줄러 — 예약마다 타이머 스레드 하나."""

    def after(self, delay_ms: int, task: Callable[[], None]) -> Cancel:
        timer = threading.Timer(max(0, delay_ms) / 1000, task)
        timer.daemon = True
        timer.start()
        return Cancel(timer.cancel)

    def sleep(self, ms: int) -> None:
        time.sleep(max(0, ms) / 1000)

    def wait(self, signal: Signal) -> None:
        signal.block()


class SecureRandom:
    """운영체제 난수(`secrets`)."""

    def random(self) -> float:
        return secrets.randbits(53) / (1 << 53)

    def uuid(self) -> str:
        return str(_uuid.uuid4())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class UrllibTransport:
    """표준 `urllib` 전송 — 시간 초과 `Rules.HTTP_TIMEOUT_SEC`, 리다이렉트를 따라가지 않는다(3xx는 그대로 돌려준다)."""

    def __init__(self, timeout_sec: float = Rules.HTTP_TIMEOUT_SEC) -> None:
        self._timeout = timeout_sec
        self._opener = urllib.request.build_opener(_NoRedirect)

    def send(self, request: HttpRequest) -> HttpResponse:
        req = urllib.request.Request(
            request.url, data=request.body, method=request.method, headers=request.headers
        )
        try:
            with self._opener.open(req, timeout=self._timeout) as res:
                return HttpResponse(res.status, {k.lower(): v for k, v in res.headers.items()}, res.read())
        except urllib.error.HTTPError as e:
            # 2xx가 아닌 응답(3xx 포함)도 응답이다
            with e:
                return HttpResponse(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read())
        except (urllib.error.URLError, OSError) as e:
            error = BydevError(Codes.NETWORK_ERROR, "API에 연결하지 못했다")
            raise error from e


class MemoryCredentialStore:
    """메모리 저장소 — 앱을 끄면 로그인이 사라진다. 클라이언트의 기본값이다(운영체제 저장소는 `bydev.platform`에서 고른다)."""

    def __init__(self, initial: CredentialRecord | None = None) -> None:
        self._record = initial
        self._lock = threading.Lock()

    def load(self) -> CredentialRecord | None:
        with self._lock:
            return self._record

    def save(self, record: CredentialRecord) -> None:
        with self._lock:
            self._record = record

    def clear(self) -> None:
        with self._lock:
            self._record = None


class NoFingerprint:
    """지문 출처 없음 — SDK가 수명 동안의 난수 ID로 물러난다(경고 로그)."""

    def read(self) -> str | None:
        return None


class SilentLog:
    """아무것도 하지 않는 로그."""

    def debug(self, message: str) -> None:
        pass

    def info(self, message: str) -> None:
        pass

    def warn(self, message: str) -> None:
        pass
