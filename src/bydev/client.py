"""데브 라이선스 API 클라이언트(명세 1 · 5 · 7절)."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ._api import Api, ApiResponse, Req
from ._generated import Codes, Routes
from ._support import sha256_hex
from ._tokens import TokenManager
from ._verifier import Verifier
from .errors import BydevError
from .login import LoginAttempt
from .models import DeviceCode, DevicePage, DeviceRelease, Entitlement, LicenseClaims, Profile, UpdateCheck
from .ports import Ports, resolve
from .session import AppInfo, DeviceInfo, LicenseSession

SDK_VERSION = "0.1.0"
USER_AGENT = f"bydev-python/{SDK_VERSION}"


@dataclass(frozen=True)
class Config:
    """명세 1절의 설정이다."""

    base_url: str
    client_id: str
    product_id: str
    scopes: Sequence[str]
    #: 세션을 쓰면 필요하다(`bydev.platform.system_device_info()`).
    device: DeviceInfo | None = None
    ports: Ports = field(default_factory=Ports)
    #: 실행 중인 앱의 배포 대상 · 버전이다 — 세션을 쓰면 넣는다(명세 1절 · ADR-0049). 위치 인수 순서를 지키려고 맨 뒤에 둔다.
    app: AppInfo | None = None


class LicenseClient:
    """데브 라이선스 API 클라이언트다. 서버 응답 하나의 참/거짓으로 기능을 열지 않는다 — `session()`의 상태와 검증된 토큰의 클레임을 쓴다.

    **블로킹 API**다(asyncio는 `bydev.aio.AsyncLicenseClient`). 스레드 사이에 나눠 쓴다.
    """

    def __init__(self, config: Config) -> None:
        if not config.scopes:
            raise BydevError(Codes.CONFIGURATION, "scopes가 비었다")
        self._config = config
        self._api = Api(config.base_url, resolve(config.ports), USER_AGENT)
        self._tokens = TokenManager(self._api, config.client_id)
        self._verifier = Verifier(self._api, config.client_id, track_generations=True)
        self._lock = threading.Lock()
        self._login: LoginAttempt | None = None
        self._session: LicenseSession | None = None

    def start_login(self) -> LoginAttempt:
        """디바이스 로그인을 시작한다(명세 5절). 진행 중인 로그인은 취소한다."""
        with self._lock:
            previous, self._login = self._login, None
        if previous is not None:
            previous.cancel()
        doc = self._api.discovery()
        body = {"client_id": self._config.client_id, "scope": " ".join(self._config.scopes)}
        res = self._api.send(Req("POST", doc.device_authorization_endpoint, body))
        attempt = LoginAttempt(DeviceCode.read(res.json), self._config.client_id, self._api, self._tokens)
        attempt.schedule_poll()
        with self._lock:
            self._login = attempt
        return attempt

    def has_credentials(self) -> bool:
        """저장된 로그인이 있는지다 — 이용 가능 여부가 아니다."""
        return self._tokens.load() is not None

    def _get(
        self, path: str, params: dict[str, str] | None = None, query: Sequence[tuple[str, str]] = ()
    ) -> Any:
        url = self._api.url(path, params, query)
        res = self._tokens.authed(lambda bearer: self._api.send(Req("GET", url, bearer=bearer)))
        self._note_lease(res)
        return res.json

    def _note_lease(self, res: ApiResponse) -> None:
        with self._lock:
            session = self._session
        if session is not None:
            session.note_lease(res.headers.get("x-lease-expires-at"))

    def entitlement(self) -> Entitlement:
        """이 제품의 이용권이다."""
        return Entitlement.read(self._get(Routes.GET_MY_ENTITLEMENT.path))

    def devices(self, cursor: str | None = None, limit: int | None = None) -> DevicePage:
        """등록된 기기 한 쪽이다. 다음 쪽을 저절로 따라가지 않는다."""
        query = []
        if cursor:
            query.append(("cursor", cursor))
        if limit is not None and limit > 0:
            query.append(("limit", str(limit)))
        return DevicePage.read(self._get(Routes.LIST_DEVICES.path, query=query))

    def release_device(self, device_id: str) -> DeviceRelease:
        """기기를 해제한다(월 횟수 제한)."""
        key = self._api.ports.random.uuid()
        url = self._api.url(Routes.RELEASE_DEVICE.path, {"deviceId": device_id})
        res = self._tokens.authed(
            lambda bearer: self._api.send(Req("DELETE", url, bearer=bearer, idempotency_key=key))
        )
        self._note_lease(res)
        return DeviceRelease.read(res.json)

    def profile(self) -> Profile:
        """닉네임과 가명 식별자다."""
        return Profile.read(self._get(Routes.GET_PROFILE.path))

    def check_for_update(self, target: str, current_version: str) -> UpdateCheck:
        """업데이트 확인이다. `update_status`가 `REQUIRED`면 업데이트 전까지 실행을 막는다. 받은 파일은 설치 전에 `verify_download`.

        `entitled`가 있으면(업데이트 제공 기한이 있는 구매자) 최상위 대신 `entitled.release`를 따른다 — 범위 밖 버전을 설치하면 세션 획득이
        거절된다.
        """
        return UpdateCheck.read(
            self._get(
                Routes.GET_PRODUCT_UPDATES.path,
                {"id": self._config.product_id},
                [("target", target), ("currentVersion", current_version)],
            )
        )

    def verify_download(self, data: bytes, sha256: str) -> None:
        """내려받은 파일의 SHA-256을 확인한다 — 다르면 `DOWNLOAD_INTEGRITY`."""
        if sha256_hex(data) != sha256.lower():
            raise BydevError(Codes.DOWNLOAD_INTEGRITY, "내려받은 파일의 SHA-256이 다르다 — 설치하지 않는다")

    def verify_token(self, token: str) -> LicenseClaims:
        """licenseToken을 검증한다(명세 9절) — 앱이 기능 코드 여러 곳에서 다시 검증할 때."""
        return self._verifier.verify_license(token, None, 0)

    def logout(self) -> bool:
        """세션을 멈추고 폐기 요청을 한 번 보낸 뒤 기록을 지운다. 서버 폐기에 성공했는지를 돌려준다."""
        with self._lock:
            login, self._login = self._login, None
            session = self._session
        if login is not None:
            login.cancel()
        if session is not None:
            session.stop()
        return self._tokens.logout()

    def session(self) -> LicenseSession:
        """이 클라이언트의 세션이다(하나뿐)."""
        with self._lock:
            if self._session is None:
                if self._config.device is None:
                    raise BydevError(Codes.CONFIGURATION, "세션을 쓰려면 device(name, platform)를 준다")
                self._session = LicenseSession(
                    self._api, self._tokens, self._verifier, self._config.device, self._config.app
                )
            return self._session
