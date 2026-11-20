"""명세 5절 — 디바이스 로그인. 코드를 받은 순간부터 폴링하고 `wait()`는 그 결과를 기다린다."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from ._api import Api, ApiResponse, Req
from ._generated import Codes, Rules, Spec
from ._support import format_iso, jittered
from ._tokens import TokenManager
from .errors import BydevError, wrap
from .models import DeviceCode, TokenSet
from .ports import Cancel, Signal


@dataclass(frozen=True)
class LoginResult:
    """로그인이 끝났을 때 받은 스코프다."""

    scope: str

    def to_dict(self) -> dict[str, Any]:
        return {"scope": self.scope}


class LoginAttempt:
    """디바이스 플로우 하나다. 화면에 `user_code` · `verification_uri_complete`(QR)를 보이고 `wait()`로 기다린다."""

    def __init__(self, code: DeviceCode, client_id: str, api: Api, tokens: TokenManager) -> None:
        self._expires_at_ms = api.ports.clock.now_ms() + code.expires_in * 1000
        self.user_code = code.user_code
        self.verification_uri = code.verification_uri
        self.verification_uri_complete = code.verification_uri_complete
        #: 코드가 만료되는 시각(ISO 8601).
        self.expires_at = format_iso(self._expires_at_ms)
        self._device_code = code.device_code
        self._client_id = client_id
        self._api = api
        self._tokens = tokens
        self._done = Signal()
        self._lock = threading.Lock()
        self._interval = code.interval
        self._settled = False
        self._handle: Cancel | None = None
        self._result: LoginResult | BydevError | None = None

    def wait(self) -> LoginResult:
        """로그인이 끝나기를 기다린다(블로킹). 실패는 `BydevError`(`EXPIRED_TOKEN` · `INVALID_GRANT` · `LOGIN_CANCELLED` · `STORAGE_FAILED` …)."""
        self._api.ports.scheduler.wait(self._done)
        with self._lock:
            result = self._result
        if isinstance(result, LoginResult):
            return result
        raise result or BydevError(Codes.LOGIN_CANCELLED, "로그인을 취소했다")

    def cancel(self) -> None:
        """로그인을 취소한다 — `wait()`는 `LOGIN_CANCELLED`로 끝난다."""
        self._finish(BydevError(Codes.LOGIN_CANCELLED, "로그인을 취소했다"))

    def _finish(self, result: LoginResult | BydevError) -> None:
        with self._lock:
            if self._settled:
                return
            self._settled = True
            self._result = result
            handle, self._handle = self._handle, None
        if handle is not None:
            handle.cancel()
        self._done.fire()

    def _is_settled(self) -> bool:
        with self._lock:
            return self._settled

    def schedule_poll(self, retry_after_sec: int = 0) -> None:
        """폴링 지터는 위로만(interval보다 이르면 SLOW_DOWN이다). 429면 retry_after_sec보다 이르게 묻지 않는다(명세 5절)."""
        ports = self._api.ports
        with self._lock:
            interval = self._interval
        delay = max(
            jittered(
                ports.random,
                max(0, interval) * 1000,
                Rules.LOGIN_POLL_JITTER_MIN,
                Rules.LOGIN_POLL_JITTER_MAX,
            ),
            retry_after_sec * 1000,
        )
        if ports.clock.now_ms() + delay > self._expires_at_ms:
            self._finish(BydevError(Codes.EXPIRED_TOKEN, "로그인 코드가 만료됐다 — 처음부터 다시"))
            return
        handle = ports.scheduler.after(delay, self._poll)
        with self._lock:
            late = self._settled
            if not late:
                self._handle = handle
        if late:
            handle.cancel()

    def _poll(self) -> None:
        if self._is_settled():
            return
        outcome: ApiResponse | BydevError
        try:
            doc = self._api.discovery()
            body = {
                "grant_type": Spec.DEVICE_CODE_GRANT_TYPE,
                "client_id": self._client_id,
                "device_code": self._device_code,
            }
            outcome = self._api.send(Req("POST", doc.token_endpoint, body))
        except Exception as e:
            outcome = wrap(e, Codes.NETWORK_ERROR, "API에 연결하지 못했다")
        if self._is_settled():
            return
        if isinstance(outcome, ApiResponse):
            try:
                tokens = TokenSet.read(outcome.json)
                self._tokens.adopt(tokens)
                self._finish(LoginResult(tokens.scope))
            except BydevError as e:
                self._finish(e)
            return
        error = outcome
        if error.code == Codes.AUTHORIZATION_PENDING:
            self.schedule_poll()
        elif error.is_transient:
            limited = error.code == Codes.RATE_LIMITED or error.http_status == 429
            self.schedule_poll((error.retry_after_sec or 0) if limited else 0)
        elif error.code == Codes.SLOW_DOWN:
            with self._lock:
                n = error.retry_after_sec
                self._interval = (
                    n if n is not None and n > 0 else self._interval + Rules.LOGIN_SLOW_DOWN_INCREMENT_SEC
                )
            self.schedule_poll()
        else:
            self._finish(error)
