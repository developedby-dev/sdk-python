"""asyncio에서 쓰는 감싸개 — 블로킹 호출을 `asyncio.to_thread`로 넘긴다. 상태 기계 · 타이머는 `LicenseClient`와 같다."""

from __future__ import annotations

import asyncio

from .client import Config, LicenseClient
from .login import LoginAttempt, LoginResult
from .models import DevicePage, DeviceRelease, Entitlement, LicenseClaims, Profile, UpdateCheck
from .session import LicenseSession


class AsyncLicenseClient:
    """`LicenseClient`의 asyncio 판이다. 세션 구독 함수는 SDK의 스레드에서 불린다 — 이벤트 루프로는 `loop.call_soon_threadsafe`로 넘긴다."""

    def __init__(self, config: Config) -> None:
        self.sync = LicenseClient(config)

    async def start_login(self) -> LoginAttempt:
        return await asyncio.to_thread(self.sync.start_login)

    async def wait_login(self, attempt: LoginAttempt) -> LoginResult:
        """`attempt.wait()`를 스레드에서 기다린다. 취소는 `attempt.cancel()`."""
        return await asyncio.to_thread(attempt.wait)

    async def has_credentials(self) -> bool:
        return await asyncio.to_thread(self.sync.has_credentials)

    async def entitlement(self) -> Entitlement:
        return await asyncio.to_thread(self.sync.entitlement)

    async def devices(self, cursor: str | None = None, limit: int | None = None) -> DevicePage:
        return await asyncio.to_thread(self.sync.devices, cursor, limit)

    async def release_device(self, device_id: str) -> DeviceRelease:
        return await asyncio.to_thread(self.sync.release_device, device_id)

    async def profile(self) -> Profile:
        return await asyncio.to_thread(self.sync.profile)

    async def check_for_update(self, target: str, current_version: str) -> UpdateCheck:
        return await asyncio.to_thread(self.sync.check_for_update, target, current_version)

    def verify_download(self, data: bytes, sha256: str) -> None:
        self.sync.verify_download(data, sha256)

    async def verify_token(self, token: str) -> LicenseClaims:
        return await asyncio.to_thread(self.sync.verify_token, token)

    async def logout(self) -> bool:
        return await asyncio.to_thread(self.sync.logout)

    def session(self) -> LicenseSession:
        """세션 — `start` · `take_over` · `retry`는 블로킹하지 않는다. `stop`은 반납을 보내니 `await asyncio.to_thread(session.stop)`."""
        return self.sync.session()
