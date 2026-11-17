"""명세 9절 — 토큰 검증 · JWKS 캐시 · 세대번호 단조 확인."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._api import Api, Req
from ._generated import Codes, Rules
from ._support import Reader, SingleFlight, b64url, loads
from .errors import BydevError
from .models import AccessClaims, LicenseClaims


@dataclass(frozen=True)
class Expectation:
    sid: str
    device_id: str
    generation: int


@dataclass(frozen=True)
class _KeySet:
    keys: dict[str, Ed25519PublicKey]
    fetched_at_ms: int
    expires_at_ms: int


def _invalid(message: str) -> BydevError:
    return BydevError(Codes.TOKEN_INVALID, message)


def _regressed(got: int, seen: int) -> BydevError:
    return BydevError(Codes.GENERATION_REGRESSED, f"세대번호 {got} < 이미 본 {seen}")


class Verifier:
    def __init__(self, api: Api, client_id: str, *, track_generations: bool) -> None:
        self._api = api
        self._client_id = client_id
        self._track = track_generations
        self._lock = threading.Lock()
        self._set: _KeySet | None = None
        self._fetching: SingleFlight[_KeySet] = SingleFlight()
        self._generations: dict[str, int] = {}

    def _verify_signed(self, token: str, typ: str) -> dict[str, Any]:
        """9절 1 ~ 4. 페이로드를 돌려준다."""
        parts = token.split(".")
        if len(parts) != 3:
            raise _invalid("JWT 형식이 아니다")
        head_raw, body_raw, sig = (b64url(p) for p in parts)
        header = loads(head_raw) if head_raw is not None else None
        payload = loads(body_raw) if body_raw is not None else None
        if not isinstance(header, dict) or not isinstance(payload, dict) or sig is None:
            raise _invalid("JWT를 읽지 못했다")
        if header.get("alg") != "EdDSA":
            raise _invalid(f"alg {header.get('alg')}")
        if header.get("typ") != typ:
            raise _invalid(f"typ {header.get('typ')}")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise _invalid("kid가 없다")
        key = self._key_for(kid)
        try:
            key.verify(sig, f"{parts[0]}.{parts[1]}".encode())
        except InvalidSignature:
            raise _invalid("서명이 맞지 않는다") from None
        doc = self._api.discovery()
        if payload.get("iss") != doc.issuer:
            raise _invalid("iss가 다르다")
        if payload.get("aud") != self._client_id:
            raise _invalid("aud가 이 client_id가 아니다")
        exp = payload.get("exp")
        now_sec = self._api.ports.clock.now_ms() / 1000
        if (
            not isinstance(exp, int | float)
            or isinstance(exp, bool)
            or exp <= now_sec - Rules.TOKEN_CLOCK_LEEWAY_SEC
        ):
            raise _invalid("만료된 토큰")
        return payload

    def verify_license(self, token: str, expect: Expectation | None, min_generation: int) -> LicenseClaims:
        payload = self._verify_signed(token, "license+jwt")
        try:
            claims = LicenseClaims.read(payload)
        except BydevError:
            raise _invalid("클레임 모양이 다르다") from None
        if expect is not None:
            if claims.sid != expect.sid:
                raise _invalid("sid가 세션과 다르다")
            if claims.device_id != expect.device_id:
                raise _invalid("device_id가 세션과 다르다")
            if claims.generation != expect.generation:
                raise _invalid("generation이 세션과 다르다")
        if min_generation > 0 and claims.generation < min_generation:
            raise _regressed(claims.generation, min_generation)
        if self._track:
            slot = f"{claims.sub}|{claims.device_id}"
            with self._lock:
                seen = self._generations.get(slot)
                if seen is None or claims.generation >= seen:
                    self._generations[slot] = claims.generation
                    seen = None
            if seen is not None:
                raise _regressed(claims.generation, seen)
        return claims

    def verify_access(self, token: str) -> AccessClaims:
        payload = self._verify_signed(token, "at+jwt")
        try:
            return AccessClaims.read(payload)
        except BydevError:
            raise _invalid("클레임 모양이 다르다") from None

    def _key_for(self, kid: str) -> Ed25519PublicKey:
        """9.1절 — 지난 캐시는 쓰지 않는다 · 모르는 kid는 1분에 한 번만 다시 받는다."""
        now = self._api.ports.clock.now_ms()
        with self._lock:
            current = self._set
        keys = current if current is not None and now < current.expires_at_ms else self._fetch_keys()
        if kid in keys.keys:
            return keys.keys[kid]
        if now - keys.fetched_at_ms < Rules.JWKS_UNKNOWN_KID_REFETCH_MIN_INTERVAL_SEC * 1000:
            raise _invalid(f"모르는 kid {kid}")
        fresh = self._fetch_keys()
        if kid not in fresh.keys:
            raise _invalid(f"모르는 kid {kid}")
        return fresh.keys[kid]

    def _fetch_keys(self) -> _KeySet:
        def fetch() -> _KeySet:
            doc = self._api.discovery()
            res = self._api.send(Req("GET", doc.jwks_uri))
            r = Reader()
            root = r.obj(res.json, "$")
            keys: dict[str, Ed25519PublicKey] = {}
            for jwk in r.items(r.get(root, "keys"), "keys"):
                if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                    continue
                kid, x = jwk.get("kid"), jwk.get("x")
                raw = b64url(x) if isinstance(x, str) else None
                if isinstance(kid, str) and kid and raw is not None and len(raw) == 32:
                    keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
                else:
                    self._api.ports.logger.warn("JWKS 키를 읽지 못했다")
            r.finish(None)
            age = Rules.JWKS_DEFAULT_MAX_AGE_SEC
            for part in res.headers.get("cache-control", "").split(","):
                part = part.strip()
                if part.startswith("max-age=") and part[8:].isdigit():
                    age = int(part[8:])
                    break
            fetched = self._api.ports.clock.now_ms()
            result = _KeySet(keys, fetched, fetched + age * 1000)
            with self._lock:
                self._set = result
            return result

        return self._fetching.run(self._api.ports.scheduler, fetch)
