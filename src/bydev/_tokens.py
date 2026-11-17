"""명세 3.5 · 3.6 · 6절 — 기록 보관 · 갱신 · 인증 요청 감싸기 · 로그아웃."""

from __future__ import annotations

import threading
from collections.abc import Callable

from ._api import Api, ApiResponse, Req
from ._generated import Codes, Rules
from ._support import SingleFlight, format_iso, seconds
from .errors import BydevError, storage
from .models import TokenSet
from .ports import CredentialRecord


class TokenManager:
    def __init__(self, api: Api, client_id: str) -> None:
        self.api = api
        self._client_id = client_id
        self._lock = threading.Lock()
        self._access: tuple[str, int] | None = None
        self._refreshing: SingleFlight[str] = SingleFlight()

    def _set_access(self, value: tuple[str, int] | None) -> None:
        with self._lock:
            self._access = value

    def load(self) -> CredentialRecord | None:
        try:
            record = self.api.ports.store.load()
        except Exception as e:
            raise storage(e, "보안 저장소를 읽지 못했다") from e
        return record if record is not None and record.version == Rules.STORAGE_RECORD_VERSION else None

    def adopt(self, tokens: TokenSet) -> None:
        """6절 3 · 5절 — 저장한 뒤에 쓴다."""
        self._set_access(None)
        ports = self.api.ports
        record = CredentialRecord(1, tokens.refresh_token, tokens.scope, format_iso(ports.clock.now_ms()))
        try:
            ports.store.save(record)
        except Exception as e:
            raise storage(e, "새 로그인을 보안 저장소에 두지 못했다 — 새 토큰을 쓰지 않는다") from e
        self._set_access((tokens.access_token, ports.clock.now_ms() + tokens.expires_in * 1000))

    def _access_token(self) -> str:
        with self._lock:
            access = self._access
        if (
            access is not None
            and access[1] - Rules.TOKEN_REFRESH_SKEW_SEC * 1000 > self.api.ports.clock.now_ms()
        ):
            return access[0]
        return self.refresh()

    def refresh(self) -> str:
        """6절 1 — 한 번에 하나."""
        self._set_access(None)
        return self._refreshing.run(self.api.ports.scheduler, self._do_refresh)

    def _do_refresh(self) -> str:
        record = self.load()
        if record is None:
            raise BydevError(Codes.NOT_SIGNED_IN, "로그인이 없다 — 먼저 로그인한다")
        doc = self.api.discovery()
        attempt = 0
        while True:
            body = {
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "refresh_token": record.refresh_token,
            }
            try:
                tokens = TokenSet.read(self.api.send(Req("POST", doc.token_endpoint, body)).json)
                self.adopt(tokens)
                return tokens.access_token
            except BydevError as e:
                if e.code == Codes.INVALID_GRANT:
                    self._forget_stored()
                    raise
                if not e.is_transient or attempt >= len(Rules.TOKEN_REFRESH_RETRY_DELAYS_SEC):
                    raise
                self.api.ports.scheduler.sleep(seconds(Rules.TOKEN_REFRESH_RETRY_DELAYS_SEC[attempt]))
                attempt += 1

    def authed(self, send: Callable[[str], ApiResponse]) -> ApiResponse:
        """3.5절 — 만료면 한 번만 갱신하고 다시 보낸다."""
        token = self._access_token()
        try:
            return send(token)
        except BydevError as e:
            if e.code != Codes.EXPIRED_TOKEN:
                raise
        fresh = self.refresh()
        try:
            return send(fresh)
        except BydevError as e:
            # 갓 받은 토큰도 거절됐다 — 다음 요청이 같은 토큰을 다시 쓰지 않게 버린다
            if e.code == Codes.EXPIRED_TOKEN:
                self._set_access(None)
            raise

    def _forget_stored(self) -> None:
        self._set_access(None)
        try:
            self.api.ports.store.clear()
        except Exception:
            self.api.ports.logger.warn("끝난 로그인의 기록을 지우지 못했다")

    def logout(self) -> bool:
        """7절 — 폐기 요청은 한 번, 결과와 상관없이 지운다. 서버가 폐기했는지를 돌려준다."""
        record = self.load()
        revoked = False
        if record is not None:
            try:
                doc = self.api.discovery()
                body = {
                    "client_id": self._client_id,
                    "token": record.refresh_token,
                    "token_type_hint": "refresh_token",
                }
                self.api.send(Req("POST", doc.revocation_endpoint, body))
                revoked = True
            except BydevError:
                revoked = False
        self._set_access(None)
        try:
            self.api.ports.store.clear()
        except Exception as e:
            raise storage(e, "로그인 기록을 지우지 못했다") from e
        return revoked
