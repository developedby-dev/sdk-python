"""명세 3 · 4절 — 요청 만들기 · 응답 읽기 · 발견 문서."""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ._generated import Codes, Routes
from ._support import SingleFlight, dumps, loads
from .errors import BydevError, wrap
from .models import Discovery
from .ports import HttpRequest, ResolvedPorts

_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _escape(text: str, *, space_plus: bool) -> str:
    """경로 조각 — 예약되지 않은 문자(A–Z a–z 0–9 - . _ ~)만 그대로."""
    out = []
    for b in text.encode():
        if b in _UNRESERVED:
            out.append(chr(b))
        elif b == 0x20 and space_plus:
            out.append("+")
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


@dataclass(frozen=True)
class ApiResponse:
    headers: dict[str, str]
    json: Any


@dataclass(frozen=True)
class Req:
    method: str
    url: str
    body: Any = None
    bearer: str | None = None
    idempotency_key: str | None = None


class Api:
    def __init__(self, base_url: str, ports: ResolvedPorts, user_agent: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.ports = ports
        self._user_agent = user_agent
        self._doc: Discovery | None = None
        self._lock = threading.Lock()
        self._discovering: SingleFlight[Discovery] = SingleFlight()

    def url(
        self, path: str, params: Mapping[str, str] | None = None, query: Sequence[tuple[str, str]] = ()
    ) -> str:
        """경로 `{이름}`을 채우고 질의를 붙인다(이름순 — 언어마다 같은 URL)."""
        out = [self.base_url]
        rest = path
        while (open_ := rest.find("{")) >= 0:
            close = rest.find("}", open_)
            close = len(rest) if close < 0 else close
            out.append(rest[:open_])
            out.append(_escape((params or {}).get(rest[open_ + 1 : close], ""), space_plus=False))
            rest = rest[close + 1 :]
        out.append(rest)
        if query:
            pairs = sorted(query, key=lambda kv: kv[0])
            out.append(
                "?"
                + "&".join(f"{_escape(k, space_plus=True)}={_escape(v, space_plus=True)}" for k, v in pairs)
            )
        return "".join(out)

    def discovery(self) -> Discovery:
        """처음 한 번 받아 클라이언트 수명 동안 둔다. 실패하면 두지 않는다(명세 4절)."""
        with self._lock:
            if self._doc is not None:
                return self._doc

        def fetch() -> Discovery:
            res = self.send(Req("GET", self.base_url + Routes.GET_OPEN_ID_CONFIGURATION.path))
            doc = Discovery.read(res.json)
            if doc.issuer.rstrip("/") != self.base_url:
                raise BydevError(
                    Codes.CONFIGURATION,
                    f"발견 문서의 issuer({doc.issuer})가 baseUrl({self.base_url})과 다르다",
                )
            with self._lock:
                self._doc = doc
            return doc

        return self._discovering.run(self.ports.scheduler, fetch)

    def send(self, req: Req) -> ApiResponse:
        headers = {"accept": "application/json", "user-agent": self._user_agent}
        body = None
        if req.body is not None:
            headers["content-type"] = "application/json"
            body = dumps(req.body).encode()
        if req.bearer is not None:
            headers["authorization"] = f"Bearer {req.bearer}"
        if req.idempotency_key is not None:
            headers["idempotency-key"] = req.idempotency_key
        try:
            res = self.ports.transport.send(HttpRequest(req.method, req.url, headers, body))
        except Exception as e:
            raise wrap(e, Codes.NETWORK_ERROR, "API에 연결하지 못했다") from e
        correlation = res.headers.get("x-correlation-id")
        parsed = loads(res.body) if res.body else None
        if 200 <= res.status < 300:
            if parsed is None:
                raise BydevError(
                    Codes.PROTOCOL_ERROR,
                    "응답 본문이 JSON이 아니다",
                    http_status=res.status,
                    correlation_id=correlation,
                )
            return ApiResponse(res.headers, parsed)
        raise _error(res.status, res.headers, parsed, correlation)


def _error(status: int, headers: Mapping[str, str], parsed: Any, correlation: str | None) -> BydevError:
    """3.2절. 실패 응답 → `BydevError`."""
    retry: int | None = None
    raw = headers.get("retry-after", "").strip()
    if raw.isdigit() and int(raw) > 0:
        retry = int(raw)
    if (
        isinstance(parsed, dict)
        and isinstance(parsed.get("code"), str)
        and isinstance(parsed.get("message"), str)
    ):
        sec = parsed.get("retryAfterSec")
        if isinstance(sec, int | float) and not isinstance(sec, bool):
            retry = int(sec)
        details = parsed.get("details")
        return BydevError(
            parsed["code"],
            parsed["message"],
            http_status=status,
            correlation_id=correlation,
            retry_after_sec=retry,
            details=details if isinstance(details, dict) else None,
        )
    code = (
        Codes.INTERNAL_ERROR
        if status >= 500
        else Codes.RATE_LIMITED
        if status == 429
        else Codes.PROTOCOL_ERROR
    )
    return BydevError(
        code, f"HTTP {status}", http_status=status, correlation_id=correlation, retry_after_sec=retry
    )
