"""명세 8절 — 라이선스 세션(실행 리스) 상태 기계. 참/거짓 하나로 이용 가능을 알리지 않는다."""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from ._api import Api, Req
from ._generated import Codes, NeedsDecisionReason, Routes, Rules, SessionStateType
from ._support import jittered, parse_iso, seconds, sha256_hex
from ._tokens import TokenManager
from ._verifier import Expectation, Verifier
from .errors import BydevError, wrap
from .models import LicenseClaims, LicenseTokenInfo, SessionInfo, read_session_response
from .ports import Cancel


@dataclass(frozen=True)
class ErrorView:
    """상태에 싣는 에러다(값으로 비교한다)."""

    code: str
    message: str
    http_status: int | None
    correlation_id: str | None
    retry_after_sec: int | None
    details: dict[str, Any] | None

    @staticmethod
    def of(e: BydevError) -> ErrorView:
        return ErrorView(e.code, e.message, e.http_status, e.correlation_id, e.retry_after_sec, e.details)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "httpStatus": self.http_status,
            "correlationId": self.correlation_id,
            "retryAfterSec": self.retry_after_sec,
            "details": self.details,
        }


@dataclass(frozen=True)
class ActiveSession:
    """지금 쓰는 다른 기기(인수 판단에 보인다)."""

    device_id: str
    device_name: str
    last_seen_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"deviceId": self.device_id, "deviceName": self.device_name, "lastSeenAt": self.last_seen_at}


def _err(e: ErrorView | None) -> dict[str, Any] | None:
    return e.to_dict() if e else None


@dataclass(frozen=True)
class Starting:
    """획득 중."""

    TYPE: ClassVar[str] = SessionStateType.STARTING
    attempt: int
    last_error: ErrorView | None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.TYPE, "attempt": self.attempt, "lastError": _err(self.last_error)}


@dataclass(frozen=True)
class Active:
    """리스를 쥔 상태 — 기능 코드는 `claims`(exp · sid)를 쓴다."""

    TYPE: ClassVar[str] = SessionStateType.ACTIVE
    session: SessionInfo
    license_token: LicenseTokenInfo
    claims: LicenseClaims

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.TYPE,
            "session": self.session.to_dict(),
            "licenseToken": self.license_token.to_dict(),
            "claims": self.claims.to_dict(),
        }


@dataclass(frozen=True)
class Degraded:
    """하트비트가 실패하는 중 — `offline_until`까지는 계속 쓸 수 있다."""

    TYPE: ClassVar[str] = SessionStateType.DEGRADED
    session: SessionInfo
    license_token: LicenseTokenInfo
    claims: LicenseClaims
    consecutive_failures: int
    offline_until: str
    last_error: ErrorView | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.TYPE,
            "session": self.session.to_dict(),
            "licenseToken": self.license_token.to_dict(),
            "claims": self.claims.to_dict(),
            "consecutiveFailures": self.consecutive_failures,
            "offlineUntil": self.offline_until,
            "lastError": _err(self.last_error),
        }


@dataclass(frozen=True)
class NeedsDecision:
    """사용자 판단이 필요하다 — `DEVICE_IN_USE` · `INSTANCE_ALREADY_RUNNING`은 `take_over()`, `DEVICE_LIMIT_EXCEEDED`는 기기 해제 뒤 `retry()`."""

    TYPE: ClassVar[str] = SessionStateType.NEEDS_DECISION
    reason: str
    active_session: ActiveSession | None
    max_devices: int | None
    correlation_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.TYPE,
            "reason": self.reason,
            "activeSession": self.active_session.to_dict() if self.active_session else None,
            "maxDevices": self.max_devices,
            "correlationId": self.correlation_id,
        }


@dataclass(frozen=True)
class Locked:
    """잠금 — 오류 화면에 `correlation_id`를 보인다. `retrying`이면 스스로 풀릴 수 있다(OFFLINE_EXPIRED)."""

    TYPE: ClassVar[str] = SessionStateType.LOCKED
    code: str
    message: str
    correlation_id: str | None
    details: dict[str, Any] | None
    retrying: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.TYPE,
            "code": self.code,
            "message": self.message,
            "correlationId": self.correlation_id,
            "details": self.details,
            "retrying": self.retrying,
        }


@dataclass(frozen=True)
class Stopped:
    """멈춤."""

    TYPE: ClassVar[str] = SessionStateType.STOPPED

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.TYPE}


#: 세션 상태(판별 유니온, 명세 8.1절) — `match state: case Active(claims=c): …`
SessionState = Starting | Active | Degraded | NeedsDecision | Locked | Stopped


@dataclass(frozen=True)
class DeviceInfo:
    """세션 획득 때 보내는 기기 정보다(`platform`은 `DevicePlatform`)."""

    name: str
    platform: str


@dataclass(frozen=True)
class AppInfo:
    """실행 중인 앱이다(명세 1절 · ADR-0049) — 배포 대상(업데이트 확인의 `target`과 같은 값, `DistributionTarget`)과 콘솔에 업로드한 버전 문자열.

    세션 획득에 싣는다. 업데이트 제공 기한이 있는 영구 이용권은 이 값이 없으면 획득이 `ENTITLEMENT_VERSION_NOT_COVERED`로 거절된다.
    """

    target: str
    version: str


class Subscription:
    """구독 — `unsubscribe()`로 끊는다."""

    def __init__(self, on_cancel: Callable[[], None]) -> None:
        self._on_cancel = on_cancel

    def unsubscribe(self) -> None:
        self._on_cancel()


class LicenseSession:
    """라이선스 세션이다. `start` · `take_over` · `retry` · `stop`과 상태 구독. 구독 함수는 SDK의 스레드에서 불린다 — UI 스레드로 넘긴다."""

    def __init__(
        self,
        api: Api,
        tokens: TokenManager,
        verifier: Verifier,
        device: DeviceInfo,
        app: AppInfo | None = None,
    ) -> None:
        self._api = api
        self._tokens = tokens
        self._verifier = verifier
        self._device = device
        self._app = app
        self._lock = threading.Lock()
        self._current: SessionState = Stopped()
        self._listeners: dict[int, Callable[[SessionState], None]] = {}
        self._next_listener = 0
        self._run = 0
        self._instance = ""
        self._held: Active | None = None
        self._failures = 0
        self._heartbeat: Cancel | None = None
        self._offline: Cancel | None = None
        self._fallback: str | None = None
        # 처음 계산한 지문 해시 — 한 실행 동안 다시 쓴다(명세 10절). 획득마다 다시 읽으면 일시적인 읽기 실패 하나로 다른 기기가 된다
        self._fingerprint: str | None = None

    def _cancel_timers(self) -> None:
        for timer in (self._heartbeat, self._offline):
            if timer is not None:
                timer.cancel()
        self._heartbeat = self._offline = None

    @property
    def state(self) -> SessionState:
        """지금 상태다."""
        with self._lock:
            return self._current

    def subscribe(self, listener: Callable[[SessionState], None]) -> Subscription:
        """상태가 바뀔 때마다 부른다."""
        with self._lock:
            key = self._next_listener
            self._next_listener += 1
            self._listeners[key] = listener

        def cancel() -> None:
            with self._lock:
                self._listeners.pop(key, None)

        return Subscription(cancel)

    def start(self) -> None:
        """`Stopped`에서만 의미가 있다(8.2절)."""
        with self._lock:
            if not isinstance(self._current, Stopped):
                return
            self._run += 1
            self._instance = self._api.ports.random.uuid()
        self._begin_acquire(force=False, last_error=None)

    def take_over(self) -> None:
        """`NeedsDecision`(다른 기기 · 같은 기기 실행 중) 또는 `Locked(SESSION_SUPERSEDED)`에서 인수한다 — 새 Idempotency-Key."""
        s = self.state
        allowed = (
            isinstance(s, NeedsDecision) and s.reason != NeedsDecisionReason.DEVICE_LIMIT_EXCEEDED
        ) or (isinstance(s, Locked) and s.code == Codes.SESSION_SUPERSEDED)
        if allowed:
            with self._lock:
                self._run += 1
            self._begin_acquire(force=True, last_error=None)

    def retry(self) -> None:
        """`NeedsDecision`(기기 수) 또는 스스로 풀리지 않는 `Locked`에서 다시 얻는다."""
        s = self.state
        allowed = (
            isinstance(s, NeedsDecision) and s.reason == NeedsDecisionReason.DEVICE_LIMIT_EXCEEDED
        ) or (isinstance(s, Locked) and not s.retrying)
        if allowed:
            with self._lock:
                self._run += 1
            self._begin_acquire(force=False, last_error=None)

    def stop(self) -> None:
        """예약을 모두 취소하고 반납을 한 번 보낸다(8.7절, 블로킹). 진행 중인 요청의 결과는 버린다."""
        with self._lock:
            if isinstance(self._current, Stopped):
                return
            self._run += 1
            self._cancel_timers()
            self._instance = ""
            sid = self._held.session.id if self._held else None
            self._held = None
        if sid is not None:
            url = self._api.url(Routes.RELEASE_SESSION.path, {"sid": sid})
            try:
                self._tokens.authed(lambda bearer: self._api.send(Req("DELETE", url, bearer=bearer)))
            except BydevError:
                self._api.ports.logger.debug("세션 반납을 보내지 못했다 — 리스가 저절로 빈다")
        self._set_state(Stopped())

    def note_lease(self, value: str | None) -> None:
        """8.5절 — 다른 인증 응답의 `X-Lease-Expires-At`."""
        if not value:
            return
        with self._lock:
            held, current = self._held, self._current
            if held is None or not isinstance(current, Active | Degraded):
                return
            if current.session.lease_expires_at == value:
                return
            session = dataclasses.replace(current.session, lease_expires_at=value)
            nxt: SessionState = dataclasses.replace(current, session=session)
            self._held = dataclasses.replace(
                held, session=dataclasses.replace(held.session, lease_expires_at=value)
            )
        self._set_state(nxt)

    # ── 안 ──────────────────────────────────────────────────────

    def _set_state(self, nxt: SessionState) -> None:
        with self._lock:
            if self._current == nxt:
                return
            self._current = nxt
            targets = list(self._listeners.values())
        for listener in targets:
            listener(nxt)

    def _live(self, run: int) -> bool:
        with self._lock:
            return self._run == run

    def _after(self, delay_ms: int, task: Callable[[], None]) -> None:
        handle = self._api.ports.scheduler.after(delay_ms, task)
        with self._lock:
            old, self._heartbeat = self._heartbeat, handle
        if old is not None:
            old.cancel()

    def _begin_acquire(self, *, force: bool, last_error: BydevError | None) -> None:
        with self._lock:
            self._cancel_timers()
            self._held = None
            self._failures = 0
            run = self._run
        self._set_state(Starting(0, ErrorView.of(last_error) if last_error else None))
        key = self._api.ports.random.uuid()
        self._after(0, lambda: self._acquire(run, force, key, 0))

    def _fingerprint_hash(self) -> str:
        with self._lock:
            if self._fingerprint is not None:
                return self._fingerprint
        computed = self._compute_fingerprint_hash()
        with self._lock:
            if self._fingerprint is None:  # 동시에 계산했으면 먼저 정한 값
                self._fingerprint = computed
            return self._fingerprint

    def _compute_fingerprint_hash(self) -> str:
        ports = self._api.ports
        try:
            source = ports.fingerprint.read()
        except Exception:
            source = None
        value = (source or "").strip()
        if not value:
            with self._lock:
                if self._fallback is None:
                    ports.logger.warn(
                        "기기 지문 출처를 읽지 못해 이번 실행 동안만 쓰는 ID를 쓴다 — 출처 포트를 준다(명세 10절)"
                    )
                    self._fallback = ports.random.uuid()
                value = self._fallback
        return sha256_hex((value + Rules.FINGERPRINT_SALT).encode())

    def _acquire(self, run: int, force: bool, key: str, attempt: int) -> None:
        """8.2절. 일시적 실패의 재시도는 같은 키."""
        if not self._live(run):
            return
        with self._lock:
            instance = self._instance
        body: dict[str, Any] = {
            "device": {
                "fingerprintHash": self._fingerprint_hash(),
                "name": self._device.name,
                "platform": self._device.platform,
            },
            "instanceId": instance,
            "force": force,
        }
        if self._app is not None:
            body["app"] = {"target": self._app.target, "version": self._app.version}
        url = self._api.url(Routes.ACQUIRE_SESSION.path)
        try:
            res = self._tokens.authed(
                lambda bearer: self._api.send(Req("POST", url, body, bearer=bearer, idempotency_key=key))
            )
            if not self._live(run):
                return
            self._adopt(run, res.json)
            return
        except Exception as e:
            if not self._live(run):
                return
            error = wrap(e, Codes.PROTOCOL_ERROR, "세션 응답을 읽지 못했다")
        if error.is_transient:
            delays = Rules.SESSION_START_RETRY_DELAYS_SEC
            base = delays[min(attempt, len(delays) - 1)]
            self._set_state(Starting(attempt + 1, ErrorView.of(error)))
            delay = jittered(
                self._api.ports.random,
                seconds(base),
                Rules.SESSION_HEARTBEAT_JITTER_MIN,
                Rules.SESSION_HEARTBEAT_JITTER_MAX,
            )
            self._after(delay, lambda: self._acquire(run, force, key, attempt + 1))
        elif error.code in Rules.NEEDS_DECISION_REASONS:
            details = error.details or {}
            raw = details.get("activeSession")
            active_session = (
                ActiveSession(
                    str(raw.get("deviceId", "")),
                    str(raw.get("deviceName", "")),
                    str(raw.get("lastSeenAt", "")),
                )
                if isinstance(raw, dict)
                else None
            )
            max_devices = details.get("maxDevices")
            self._set_state(
                NeedsDecision(
                    error.code,
                    active_session,
                    int(max_devices) if isinstance(max_devices, int | float) else None,
                    error.correlation_id,
                )
            )
        else:
            self._lock_with(error, retrying=False)

    def _adopt(self, run: int, json: Any) -> None:
        """200 응답 → 검증(9절) → Active → 다음 하트비트."""
        session, token = read_session_response(json)
        claims = self._verifier.verify_license(
            token.token, Expectation(session.id, session.device_id, session.generation), 0
        )
        if not self._live(run):
            return
        active = Active(session, token, claims)
        with self._lock:
            self._held = active
            self._failures = 0
            offline, self._offline = self._offline, None
        if offline is not None:
            offline.cancel()
        self._set_state(active)
        self._schedule_heartbeat(run, session.heartbeat_sec, 0)

    def _schedule_heartbeat(self, run: int, heartbeat_sec: int, retry_after_sec: int) -> None:
        delay = max(
            jittered(
                self._api.ports.random,
                max(0, heartbeat_sec) * 1000,
                Rules.SESSION_HEARTBEAT_JITTER_MIN,
                Rules.SESSION_HEARTBEAT_JITTER_MAX,
            ),
            retry_after_sec * 1000,
        )
        self._after(delay, lambda: self._beat(run))

    def _beat(self, run: int) -> None:
        """8.3절 하트비트."""
        with self._lock:
            held = self._held if self._run == run else None
        if held is None:
            return
        url = self._api.url(Routes.HEARTBEAT_SESSION.path, {"sid": held.session.id})
        body = {"generation": held.session.generation}
        try:
            res = self._tokens.authed(lambda bearer: self._api.send(Req("POST", url, body, bearer=bearer)))
            if not self._live(run):
                return
            self._adopt(run, res.json)
            return
        except Exception as e:
            if not self._live(run):
                return
            error = wrap(e, Codes.PROTOCOL_ERROR, "세션 응답을 읽지 못했다")
        if error.is_transient:
            with self._lock:
                self._failures += 1
                failures = self._failures
                holding = isinstance(self._current, Active | Degraded)
            if holding:
                offline_until = held.license_token.expires_at
                self._set_state(
                    Degraded(
                        held.session,
                        held.license_token,
                        held.claims,
                        failures,
                        offline_until,
                        ErrorView.of(error),
                    )
                )
                self._arm_offline_expiry(run, offline_until)
            retry = (
                error.retry_after_sec or 0
                if error.code == Codes.RATE_LIMITED or error.http_status == 429
                else 0
            )
            self._schedule_heartbeat(run, held.session.heartbeat_sec, retry)
        elif error.code == Codes.SESSION_REVOKED:
            # 리스가 끝났을 때도 이 코드다 — 한 번 다시 얻는다(같은 instanceId, 새 키)
            self._begin_acquire(force=False, last_error=error)
        else:
            self._lock_with(error, retrying=False)

    def _arm_offline_expiry(self, run: int, offline_until: str) -> None:
        """8.4절 — `offline_until`이 지나도록 성공하지 못하면 잠근다. 재시도는 그대로."""
        with self._lock:
            if self._offline is not None:
                return
        now = self._api.ports.clock.now_ms()
        until = parse_iso(offline_until)
        delay = max(0, until - now) if until is not None else 0

        def expire() -> None:
            with self._lock:
                self._offline = None
                ok = self._run == run and isinstance(self._current, Degraded)
            if ok:
                self._set_state(
                    Locked(
                        Codes.OFFLINE_EXPIRED,
                        "하트비트에 성공하지 못한 채 licenseToken이 만료됐다",
                        None,
                        None,
                        True,
                    )
                )

        handle = self._api.ports.scheduler.after(delay, expire)
        with self._lock:
            self._offline = handle

    def _lock_with(self, error: BydevError, *, retrying: bool) -> None:
        with self._lock:
            self._cancel_timers()
        self._set_state(Locked(error.code, error.message, error.correlation_id, error.details, retrying))
