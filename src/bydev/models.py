"""공개 API 응답의 SDK 모델.

속성은 Python 이름(snake_case), `to_dict()`는 contracts 모양(camelCase — 기록 · 진단용)이다. 열거 값은 `str`(모르는 값도 — 명세 0절 5, 아는 값은
생성된 `EntitlementStatus` 등).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._generated import InstallMode, UpdateCoverageType
from ._support import Reader, dumps


class _Model:
    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    def to_json(self) -> str:
        return dumps(self.to_dict())


@dataclass(frozen=True)
class EntitlementTerm(_Model):
    """기간이다. `type`을 먼저 분기한다 — 영구(`PERPETUAL`)는 잔여 필드가 None이다."""

    type: str
    expires_at: str | None
    remaining_days: int | None
    remaining_seconds: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "expiresAt": self.expires_at,
            "remainingDays": self.remaining_days,
            "remainingSeconds": self.remaining_seconds,
        }


@dataclass(frozen=True)
class EntitlementSubscription(_Model):
    """구독형일 때만 있다."""

    id: str
    status: str
    will_renew: bool
    next_billing_at: str | None
    grace_ends_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "willRenew": self.will_renew,
            "nextBillingAt": self.next_billing_at,
            "graceEndsAt": self.grace_ends_at,
        }


@dataclass(frozen=True)
class LicensePolicy(_Model):
    """판매자가 정한 정책 수치다 — 앱에 하드코딩하지 않는다."""

    max_devices: int
    max_concurrent: int
    heartbeat_sec: int
    offline_grace_hours: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "maxDevices": self.max_devices,
            "maxConcurrent": self.max_concurrent,
            "heartbeatSec": self.heartbeat_sec,
            "offlineGraceHours": self.offline_grace_hours,
        }


@dataclass(frozen=True)
class UpdateCoverage(_Model):
    """업데이트 제공 범위다(ADR-0049). `type`을 먼저 분기한다 — `UNTIL`이면 `until` 전에 출시된 버전을 실행할 수 있다. 모르는 `type`이면
    `type`만 담기고 `until`은 None이다(`UpdateCoverageType`)."""

    type: str
    until: str | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.type == UpdateCoverageType.UNTIL:
            return {"type": self.type, "until": self.until}
        return {"type": self.type}


@dataclass(frozen=True)
class Entitlement(_Model):
    """이 제품의 이용권이다."""

    id: str
    product_id: str
    status: str
    term: EntitlementTerm
    subscription: EntitlementSubscription | None
    policy: LicensePolicy
    evaluated_at: str
    #: 업데이트 제공 범위 — 응답에는 늘 있다. 직접 만들 때 주지 않으면 1.1 전과 같은 「모든 업데이트 포함」(`ALL`)이다.
    update_coverage: UpdateCoverage = UpdateCoverage(UpdateCoverageType.ALL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "productId": self.product_id,
            "status": self.status,
            "term": self.term.to_dict(),
            "updateCoverage": self.update_coverage.to_dict(),
            "subscription": self.subscription.to_dict() if self.subscription else None,
            "policy": self.policy.to_dict(),
            "evaluatedAt": self.evaluated_at,
        }

    @staticmethod
    def read(json: Any) -> Entitlement:
        r = Reader()
        e = r.obj(r.get(r.obj(json, "$"), "entitlement"), "entitlement")
        t = r.obj(r.get(e, "term"), "entitlement.term")
        kind = r.text(r.get(t, "type"), "entitlement.term.type")
        term = EntitlementTerm(kind, None, None, None)
        if kind != "PERPETUAL":
            term = EntitlementTerm(
                kind,
                r.opt_text(r.get(t, "expiresAt"), "entitlement.term.expiresAt"),
                r.opt_integer(r.get(t, "remainingDays"), "entitlement.term.remainingDays"),
                r.opt_integer(r.get(t, "remainingSeconds"), "entitlement.term.remainingSeconds"),
            )
        c = r.obj(r.get(e, "updateCoverage"), "entitlement.updateCoverage")
        coverage_type = r.text(r.get(c, "type"), "entitlement.updateCoverage.type")
        coverage = UpdateCoverage(coverage_type)
        if coverage_type == UpdateCoverageType.UNTIL:
            coverage = UpdateCoverage(
                coverage_type, r.text(r.get(c, "until"), "entitlement.updateCoverage.until")
            )
        p = r.obj(r.get(e, "policy"), "entitlement.policy")
        policy = LicensePolicy(
            r.integer(r.get(p, "maxDevices"), "entitlement.policy.maxDevices"),
            r.integer(r.get(p, "maxConcurrent"), "entitlement.policy.maxConcurrent"),
            r.integer(r.get(p, "heartbeatSec"), "entitlement.policy.heartbeatSec"),
            r.integer(r.get(p, "offlineGraceHours"), "entitlement.policy.offlineGraceHours"),
        )
        subscription = None
        sub = e.get("subscription")
        if sub is not None:
            s = r.obj(sub, "entitlement.subscription")
            subscription = EntitlementSubscription(
                r.text(r.get(s, "id"), "entitlement.subscription.id"),
                r.text(r.get(s, "status"), "entitlement.subscription.status"),
                r.flag(r.get(s, "willRenew"), "entitlement.subscription.willRenew"),
                r.opt_text(r.get(s, "nextBillingAt"), "entitlement.subscription.nextBillingAt"),
                r.opt_text(r.get(s, "graceEndsAt"), "entitlement.subscription.graceEndsAt"),
            )
        return r.finish(
            Entitlement(
                r.text(r.get(e, "id"), "entitlement.id"),
                r.text(r.get(e, "productId"), "entitlement.productId"),
                r.text(r.get(e, "status"), "entitlement.status"),
                term,
                subscription,
                policy,
                r.text(r.get(e, "evaluatedAt"), "entitlement.evaluatedAt"),
                coverage,
            )
        )


@dataclass(frozen=True)
class Device(_Model):
    """등록된 기기다."""

    id: str
    name: str
    platform: str
    registered_at: str
    last_seen_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "platform": self.platform,
            "registeredAt": self.registered_at,
            "lastSeenAt": self.last_seen_at,
        }


@dataclass(frozen=True)
class DevicePage(_Model):
    """기기 목록 한 쪽이다. `next_cursor`가 None이면 마지막 쪽이다."""

    items: tuple[Device, ...]
    next_cursor: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"items": [d.to_dict() for d in self.items], "nextCursor": self.next_cursor}

    @staticmethod
    def read(json: Any) -> DevicePage:
        r = Reader()
        page = r.obj(json, "$")
        items = []
        for v in r.items(r.get(page, "items"), "items"):
            d = r.obj(v, "items[]")
            items.append(
                Device(
                    r.text(r.get(d, "id"), "items[].id"),
                    r.text(r.get(d, "name"), "items[].name"),
                    r.text(r.get(d, "platform"), "items[].platform"),
                    r.text(r.get(d, "registeredAt"), "items[].registeredAt"),
                    r.text(r.get(d, "lastSeenAt"), "items[].lastSeenAt"),
                )
            )
        return r.finish(DevicePage(tuple(items), r.opt_text(r.get(page, "nextCursor"), "nextCursor")))


@dataclass(frozen=True)
class DeviceRelease(_Model):
    """기기 해제 결과다."""

    id: str
    status: str
    released_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "status": self.status, "releasedAt": self.released_at}

    @staticmethod
    def read(json: Any) -> DeviceRelease:
        r = Reader()
        d = r.obj(r.get(r.obj(json, "$"), "device"), "device")
        return r.finish(
            DeviceRelease(
                r.text(r.get(d, "id"), "device.id"),
                r.text(r.get(d, "status"), "device.status"),
                r.text(r.get(d, "releasedAt"), "device.releasedAt"),
            )
        )


@dataclass(frozen=True)
class Profile(_Model):
    """닉네임과 가명 식별자다. `pseudonymous_id`를 판매자 쪽 고객 키로 쓴다."""

    pseudonymous_id: str
    nickname: str
    email: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"pseudonymousId": self.pseudonymous_id, "nickname": self.nickname, "email": self.email}

    @staticmethod
    def read(json: Any) -> Profile:
        r = Reader()
        p = r.obj(r.get(r.obj(json, "$"), "profile"), "profile")
        return r.finish(
            Profile(
                r.text(r.get(p, "pseudonymousId"), "profile.pseudonymousId"),
                r.text(r.get(p, "nickname"), "profile.nickname"),
                r.opt_text(r.get(p, "email"), "profile.email"),
            )
        )


@dataclass(frozen=True)
class ExternalChannel(_Model):
    """외부 채널의 설치 위치다."""

    channel: str
    locator: str

    def to_dict(self) -> dict[str, Any]:
        return {"channel": self.channel, "locator": self.locator}


@dataclass(frozen=True)
class ProductInstall(_Model):
    """설치 방법이다. `mode`가 `HOSTED`면 내려받기 필드가, `EXTERNAL`이면 `channels`가 있다. 모르는 방식이면 `mode`만."""

    mode: str
    build_id: str | None = None
    download_url: str | None = None
    download_url_expires_at: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    channels: tuple[ExternalChannel, ...] | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.mode == InstallMode.HOSTED:
            return {
                "mode": self.mode,
                "buildId": self.build_id,
                "downloadUrl": self.download_url,
                "downloadUrlExpiresAt": self.download_url_expires_at,
                "sha256": self.sha256,
                "sizeBytes": self.size_bytes,
            }
        if self.mode == InstallMode.EXTERNAL:
            return {"mode": self.mode, "channels": [c.to_dict() for c in self.channels or ()]}
        return {"mode": self.mode}


@dataclass(frozen=True)
class UpdateLatest(_Model):
    """최신 버전."""

    version: str
    released_at: str
    notes: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "releasedAt": self.released_at, "notes": self.notes}


def _read_install(r: Reader, json: Any, path: str) -> ProductInstall:
    i = r.obj(json, path)
    mode = r.text(r.get(i, "mode"), f"{path}.mode")
    if mode == InstallMode.HOSTED:
        return ProductInstall(
            mode,
            build_id=r.text(r.get(i, "buildId"), f"{path}.buildId"),
            download_url=r.text(r.get(i, "downloadUrl"), f"{path}.downloadUrl"),
            download_url_expires_at=r.text(r.get(i, "downloadUrlExpiresAt"), f"{path}.downloadUrlExpiresAt"),
            sha256=r.text(r.get(i, "sha256"), f"{path}.sha256"),
            size_bytes=r.integer(r.get(i, "sizeBytes"), f"{path}.sizeBytes"),
        )
    if mode == InstallMode.EXTERNAL:
        channels = []
        for v in r.items(r.get(i, "channels"), f"{path}.channels"):
            c = r.obj(v, f"{path}.channels[]")
            channels.append(
                ExternalChannel(
                    r.text(r.get(c, "channel"), f"{path}.channels[].channel"),
                    r.text(r.get(c, "locator"), f"{path}.channels[].locator"),
                )
            )
        return ProductInstall(mode, channels=tuple(channels))
    return ProductInstall(mode)


def _read_latest(r: Reader, json: Any, path: str) -> UpdateLatest:
    latest = r.obj(json, path)
    return UpdateLatest(
        r.text(r.get(latest, "version"), f"{path}.version"),
        r.text(r.get(latest, "releasedAt"), f"{path}.releasedAt"),
        r.opt_text(r.get(latest, "notes"), f"{path}.notes"),
    )


def _read_status(r: Reader, json: Any, path: str) -> str:
    return r.text(r.get(r.obj(json, path), "status"), f"{path}.status")


@dataclass(frozen=True)
class UpdateRelease(_Model):
    """최신 버전 · 업데이트 판정 · 설치 방법이다 — 업데이트 확인의 최상위와 `entitled.release`가 같은 모양이다."""

    latest: UpdateLatest
    #: `UP_TO_DATE` · `AVAILABLE` · `REQUIRED` …(`UpdateStatus`)
    update_status: str
    install: ProductInstall

    def to_dict(self) -> dict[str, Any]:
        return {
            "latest": self.latest.to_dict(),
            "update": {"status": self.update_status},
            "install": self.install.to_dict(),
        }


@dataclass(frozen=True)
class EntitledUpdate(_Model):
    """업데이트 제공 기한이 있는 구매자에게만 오는 값이다(ADR-0049 4절).

    있으면 앱은 업데이트 확인의 최상위 `latest` · `update_status` · `install` 대신 `release`를 따른다 — 최상위 최신은 그 구매자가 실행할
    수 없는 버전일 수 있고, 범위 밖 버전을 설치하면 세션 획득이 `ENTITLEMENT_VERSION_NOT_COVERED`로 거절된다. 이 대상에 범위 안 버전이
    없으면 `release`는 None이다.
    """

    covered_until: str
    release: UpdateRelease | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "coveredUntil": self.covered_until,
            "release": self.release.to_dict() if self.release else None,
        }


@dataclass(frozen=True)
class UpdateCheck(_Model):
    """업데이트 확인 결과다. `update_status`가 `REQUIRED`면 업데이트 전까지 실행을 막는다. `entitled`가 있으면 그쪽을 따른다."""

    product_id: str
    target: str
    latest: UpdateLatest
    #: `UP_TO_DATE` · `AVAILABLE` · `REQUIRED` …(`UpdateStatus`)
    update_status: str
    install: ProductInstall
    #: 업데이트 제공 기한이 있는 구매자에게만 있다(`EntitledUpdate`). 없으면 None.
    entitled: EntitledUpdate | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "product": {"id": self.product_id},
            "target": self.target,
            "latest": self.latest.to_dict(),
            "update": {"status": self.update_status},
            "install": self.install.to_dict(),
        }
        if self.entitled is not None:
            out["entitled"] = self.entitled.to_dict()
        return out

    @staticmethod
    def read(json: Any) -> UpdateCheck:
        r = Reader()
        o = r.obj(json, "$")
        product_id = r.text(r.get(r.obj(r.get(o, "product"), "product"), "id"), "product.id")
        target = r.text(r.get(o, "target"), "target")
        latest = _read_latest(r, r.get(o, "latest"), "latest")
        status = _read_status(r, r.get(o, "update"), "update")
        install = _read_install(r, r.get(o, "install"), "install")
        entitled = None
        raw = o.get("entitled")
        if raw is not None:
            e = r.obj(raw, "entitled")
            release = None
            rel = e.get("release")
            if rel is not None:
                rr = r.obj(rel, "entitled.release")
                release = UpdateRelease(
                    _read_latest(r, r.get(rr, "latest"), "entitled.release.latest"),
                    _read_status(r, r.get(rr, "update"), "entitled.release.update"),
                    _read_install(r, r.get(rr, "install"), "entitled.release.install"),
                )
            entitled = EntitledUpdate(r.text(r.get(e, "coveredUntil"), "entitled.coveredUntil"), release)
        return r.finish(UpdateCheck(product_id, target, latest, status, install, entitled))


@dataclass(frozen=True)
class SessionInfo(_Model):
    """세션(실행 리스)이다."""

    id: str
    product_id: str
    device_id: str
    generation: int
    lease_expires_at: str
    heartbeat_sec: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "productId": self.product_id,
            "deviceId": self.device_id,
            "generation": self.generation,
            "leaseExpiresAt": self.lease_expires_at,
            "heartbeatSec": self.heartbeat_sec,
        }


@dataclass(frozen=True)
class LicenseTokenInfo(_Model):
    """세션 보유 증명 JWT와 그 만료(오프라인 유예의 끝)다."""

    token: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"token": self.token, "expiresAt": self.expires_at}


def read_session_response(json: Any) -> tuple[SessionInfo, LicenseTokenInfo]:
    r = Reader()
    o = r.obj(json, "$")
    s = r.obj(r.get(o, "session"), "session")
    t = r.obj(r.get(o, "licenseToken"), "licenseToken")
    session = SessionInfo(
        r.text(r.get(s, "id"), "session.id"),
        r.text(r.get(s, "productId"), "session.productId"),
        r.text(r.get(s, "deviceId"), "session.deviceId"),
        r.integer(r.get(s, "generation"), "session.generation"),
        r.text(r.get(s, "leaseExpiresAt"), "session.leaseExpiresAt"),
        r.integer(r.get(s, "heartbeatSec"), "session.heartbeatSec"),
    )
    token = LicenseTokenInfo(
        r.text(r.get(t, "token"), "licenseToken.token"),
        r.text(r.get(t, "expiresAt"), "licenseToken.expiresAt"),
    )
    return r.finish((session, token))


@dataclass(frozen=True)
class LicenseClaims(_Model):
    """검증된 licenseToken 클레임이다(명세 9절). `to_dict()` 이름은 JWT 그대로(`product_id` · `device_id`)."""

    iss: str
    sub: str
    aud: str
    product_id: str
    device_id: str
    sid: str
    generation: int
    iat: int
    exp: int
    #: 세션을 얻을 때 앱이 보낸 대상 · 버전으로 서버가 확정한 빌드다(ADR-0049). 확정하지 못했으면 None.
    build_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "product_id": self.product_id,
            "device_id": self.device_id,
            "sid": self.sid,
            "generation": self.generation,
            "iat": self.iat,
            "exp": self.exp,
        }
        if self.build_id is not None:
            out["build_id"] = self.build_id
        return out

    @staticmethod
    def read(json: Any) -> LicenseClaims:
        r = Reader()
        c = r.obj(json, "claims")
        return r.finish(
            LicenseClaims(
                r.text(r.get(c, "iss"), "claims.iss"),
                r.text(r.get(c, "sub"), "claims.sub"),
                r.text(r.get(c, "aud"), "claims.aud"),
                r.text(r.get(c, "product_id"), "claims.product_id"),
                r.text(r.get(c, "device_id"), "claims.device_id"),
                r.text(r.get(c, "sid"), "claims.sid"),
                r.integer(r.get(c, "generation"), "claims.generation"),
                r.integer(r.get(c, "iat"), "claims.iat"),
                r.integer(r.get(c, "exp"), "claims.exp"),
                r.opt_text(r.get(c, "build_id"), "claims.build_id"),
            )
        )


@dataclass(frozen=True)
class AccessClaims(_Model):
    """검증된 access_token 클레임이다(명세 12절 — 판매자 서버)."""

    iss: str
    sub: str
    aud: str
    client_id: str
    scope: str
    iat: int
    exp: int
    jti: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "client_id": self.client_id,
            "scope": self.scope,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
        }

    @staticmethod
    def read(json: Any) -> AccessClaims:
        r = Reader()
        c = r.obj(json, "claims")
        return r.finish(
            AccessClaims(
                r.text(r.get(c, "iss"), "claims.iss"),
                r.text(r.get(c, "sub"), "claims.sub"),
                r.text(r.get(c, "aud"), "claims.aud"),
                r.text(r.get(c, "client_id"), "claims.client_id"),
                r.text(r.get(c, "scope"), "claims.scope"),
                r.integer(r.get(c, "iat"), "claims.iat"),
                r.integer(r.get(c, "exp"), "claims.exp"),
                r.text(r.get(c, "jti"), "claims.jti"),
            )
        )


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    expires_in: int
    refresh_token: str
    scope: str

    @staticmethod
    def read(json: Any) -> TokenSet:
        r = Reader()
        t = r.obj(json, "$")
        return r.finish(
            TokenSet(
                r.text(r.get(t, "access_token"), "access_token"),
                r.integer(r.get(t, "expires_in"), "expires_in"),
                r.text(r.get(t, "refresh_token"), "refresh_token"),
                r.text(r.get(t, "scope"), "scope"),
            )
        )


@dataclass(frozen=True)
class DeviceCode:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int

    @staticmethod
    def read(json: Any) -> DeviceCode:
        r = Reader()
        d = r.obj(json, "$")
        return r.finish(
            DeviceCode(
                r.text(r.get(d, "device_code"), "device_code"),
                r.text(r.get(d, "user_code"), "user_code"),
                r.text(r.get(d, "verification_uri"), "verification_uri"),
                r.text(r.get(d, "verification_uri_complete"), "verification_uri_complete"),
                r.integer(r.get(d, "expires_in"), "expires_in"),
                r.integer(r.get(d, "interval"), "interval"),
            )
        )


@dataclass(frozen=True)
class Discovery:
    issuer: str
    jwks_uri: str
    device_authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str

    @staticmethod
    def read(json: Any) -> Discovery:
        r = Reader()
        d = r.obj(json, "$")
        return r.finish(
            Discovery(
                r.text(r.get(d, "issuer"), "issuer"),
                r.text(r.get(d, "jwks_uri"), "jwks_uri"),
                r.text(r.get(d, "device_authorization_endpoint"), "device_authorization_endpoint"),
                r.text(r.get(d, "token_endpoint"), "token_endpoint"),
                r.text(r.get(d, "revocation_endpoint"), "revocation_endpoint"),
            )
        )
