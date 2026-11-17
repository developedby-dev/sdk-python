"""명세 12절 — 판매자 서버 도우미(웹훅 서명 · 토큰 검증). 앱 쪽 클라이언트와 상태를 나누지 않는다."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ._api import Api
from ._generated import Codes, Rules
from ._verifier import Verifier
from .client import USER_AGENT
from .defaults import SystemClock
from .errors import BydevError
from .models import AccessClaims, LicenseClaims
from .ports import Ports, WallClock, resolve


@dataclass(frozen=True)
class WebhookVerification:
    """검증된 웹훅의 id와 시각이다. 중복 수신은 id로 거른다."""

    id: str
    timestamp: int


def verify_webhook(
    secrets: Sequence[str],
    headers: Mapping[str, str],
    raw_body: bytes | str,
    clock: WallClock | None = None,
) -> WebhookVerification:
    """서명을 검증한다(안내서 11장 · Standard Webhooks v1).

    `raw_body`는 받은 그대로의 본문이다 — 파싱했다가 다시 만든 바이트는 서명이 맞지 않는다. 시크릿을 교체하는 중이면 둘 다 넘긴다. 헤더 이름의
    대소문자는 가리지 않는다.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    wid, timestamp, signatures = (
        lowered.get(k) for k in ("webhook-id", "webhook-timestamp", "webhook-signature")
    )
    if not wid or not timestamp or not signatures:
        raise BydevError(
            Codes.WEBHOOK_INVALID, "웹훅 헤더(webhook-id · webhook-timestamp · webhook-signature)가 없다"
        )
    now_sec = (clock or SystemClock()).now_ms() / 1000
    if not timestamp.isdigit() or abs(now_sec - int(timestamp)) > Rules.WEBHOOK_TOLERANCE_SEC:
        raise BydevError(Codes.WEBHOOK_INVALID, "웹훅 시각이 허용 범위 밖이다 — 재전송 공격일 수 있다")
    candidates = []
    for entry in signatures.split(" "):
        version, _, value = entry.partition(",")
        if version != Rules.WEBHOOK_SIGNATURE_VERSION or not value:
            continue
        try:
            candidates.append(base64.b64decode(value, validate=True))
        except (binascii.Error, ValueError):
            continue
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    signed = f"{wid}.{timestamp}.".encode() + body
    for secret in secrets:
        if not secret.startswith(Rules.WEBHOOK_SECRET_PREFIX):
            raise BydevError(Codes.CONFIGURATION, f"웹훅 시크릿은 {Rules.WEBHOOK_SECRET_PREFIX}로 시작한다")
        try:
            key = base64.b64decode(secret[len(Rules.WEBHOOK_SECRET_PREFIX) :], validate=True)
        except (binascii.Error, ValueError) as e:
            raise BydevError(Codes.CONFIGURATION, "웹훅 시크릿을 읽지 못했다") from e
        expected = hmac.new(key, signed, hashlib.sha256).digest()
        if any(hmac.compare_digest(c, expected) for c in candidates):
            return WebhookVerification(wid, int(timestamp))
    raise BydevError(Codes.WEBHOOK_INVALID, "웹훅 서명이 맞지 않는다")


class ServerVerifier:
    """판매자 서버의 토큰 검증이다(안내서 09장) — JWKS를 받아 캐시한다. 인스턴스 하나를 오래 쓴다. `ports`는 전송 · 시계만 쓴다."""

    def __init__(self, base_url: str, client_id: str, ports: Ports | None = None) -> None:
        self._verifier = Verifier(
            Api(base_url, resolve(ports or Ports()), USER_AGENT), client_id, track_generations=False
        )

    def verify_access_token(self, token: str) -> AccessClaims:
        """access_token(at+jwt)을 검증한다."""
        return self._verifier.verify_access(token)

    def verify_license_token(self, token: str, min_generation: int = 0) -> LicenseClaims:
        """licenseToken을 검증한다. min_generation — 같은 sub · device_id에서 이미 본 가장 큰 세대번호(0이면 보지 않는다)."""
        return self._verifier.verify_license(token, None, min_generation)
