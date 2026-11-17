"""판매자 서버 도우미 — 웹훅 서명 · 토큰 검증(실제 소켓 · 기본 전송)."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from bydev import BydevError, Codes, Ports, ServerVerifier, WebhookVerification, verify_webhook

# 안내서 11장의 서명 예시 — 문서와 SDK가 같은 값으로 맞는다(TS · Go · .NET · Kotlin 시험과 같은 값).
SECRET = "whsec_/MU12AiKByBoT7xt+p81N/uKdp/WxQRb"
ID = "evt_01J9MC4D6E8F0G2H4J6K8M0N2P"
SENT = 1791295205
BODY = '{"id":"evt_01J9MC4D6E8F0G2H4J6K8M0N2P","type":"build.review_completed","occurredAt":"2026-10-06T14:00:00Z","mode":"LIVE","simulated":false,"data":{"build":{"id":"build_01J9M4D6F8H0J2K4M6N8P0R2S4","productId":"prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD","version":"1.4.2","reviewedAt":"2026-10-06T13:58:00Z","result":"APPROVED"}}}'
SIGNATURE = "v1,vmsiq2HY4gik/WNJjXJzuESzXAjJgr8Vi13SKwwhgEo="


class _At:
    def __init__(self, sec: int) -> None:
        self._ms = sec * 1000

    def now_ms(self) -> int:
        return self._ms


def headers(sig: str) -> dict[str, str]:
    return {"Webhook-Id": ID, "Webhook-Timestamp": str(SENT), "Webhook-Signature": sig}


def rejects(code: str, verify: Callable[[], object]) -> None:
    with pytest.raises(BydevError) as caught:
        verify()
    assert caught.value.code == code


def test_webhook_guide_example() -> None:
    assert verify_webhook([SECRET], headers(SIGNATURE), BODY, _At(SENT + 10)) == WebhookVerification(ID, SENT)
    assert verify_webhook([SECRET], headers(SIGNATURE), BODY.encode(), _At(SENT)).id == ID


def test_webhook_rotation() -> None:
    # 서명 여러 개 · 시크릿 여러 개 중 하나라도 맞으면
    verify_webhook([SECRET], headers(f"v1,AAAA {SIGNATURE}"), BODY, _At(SENT))
    verify_webhook(["whsec_AAAAAAAAAAAAAAAAAAAAAAAA", SECRET], headers(SIGNATURE), BODY, _At(SENT))


def test_webhook_rejects_tampering_replay_and_missing_headers() -> None:
    rejects(
        Codes.WEBHOOK_INVALID, lambda: verify_webhook([SECRET], headers(SIGNATURE), BODY + " ", _At(SENT))
    )
    rejects(
        Codes.WEBHOOK_INVALID, lambda: verify_webhook([SECRET], headers(SIGNATURE), BODY, _At(SENT + 301))
    )
    rejects(
        Codes.WEBHOOK_INVALID, lambda: verify_webhook([SECRET], headers(SIGNATURE), BODY, _At(SENT - 301))
    )
    rejects(Codes.WEBHOOK_INVALID, lambda: verify_webhook([SECRET], {"webhook-id": ID}, BODY, _At(SENT)))
    rejects(
        Codes.WEBHOOK_INVALID,
        lambda: verify_webhook([SECRET], headers("v2," + SIGNATURE[3:]), BODY, _At(SENT)),
    )
    # 접두사 없는 시크릿은 설정 실수
    rejects(
        Codes.CONFIGURATION,
        lambda: verify_webhook(["/MU12AiKByBoT7xt+p81N/uKdp/WxQRb"], headers(SIGNATURE), BODY, _At(SENT)),
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


CLIENT_ID = "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW"
NOW = 1791295205


class _Server:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.jwks_hits = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                base = outer.base
                body: dict[str, object]
                if self.path == "/.well-known/openid-configuration":
                    status, body = (
                        200,
                        {
                            "issuer": base,
                            "jwks_uri": f"{base}/.well-known/jwks.json",
                            "device_authorization_endpoint": f"{base}/v1/oauth/device/code",
                            "token_endpoint": f"{base}/v1/oauth/token",
                            "revocation_endpoint": f"{base}/v1/oauth/revoke",
                        },
                    )
                elif self.path == "/.well-known/jwks.json":
                    outer.jwks_hits += 1
                    x = _b64(outer.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
                    key = {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "kid": "srv-k1",
                        "use": "sig",
                        "alg": "EdDSA",
                        "x": x,
                    }
                    status, body = 200, {"keys": [key]}
                else:
                    status, body = 404, {"code": "PRODUCT_NOT_FOUND", "message": "없음"}
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.http.server_address[1]}"
        threading.Thread(target=self.http.serve_forever, daemon=True).start()

    def mint(self, kid: str, aud: str) -> str:
        head = {"alg": "EdDSA", "typ": "at+jwt", "kid": kid}
        claims = {
            "iss": self.base,
            "sub": "usr_01J9M0Y6X4N3Q8ZD5R2KT7VCPW",
            "aud": aud,
            "client_id": aud,
            "scope": "entitlement.read",
            "iat": NOW,
            "exp": NOW + 3600,
            "jti": "at_srv0001",
        }
        signing = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(claims).encode())}"
        return f"{signing}.{_b64(self.key.sign(signing.encode()))}"


@pytest.fixture
def server() -> Iterator[_Server]:
    s = _Server()
    yield s
    s.http.shutdown()
    s.http.server_close()


def test_server_verifier_verifies_access_tokens(server: _Server) -> None:
    verifier = ServerVerifier(server.base, CLIENT_ID, Ports(clock=_At(NOW)))
    got = verifier.verify_access_token(server.mint("srv-k1", CLIENT_ID))
    assert (got.sub, got.scope) == ("usr_01J9M0Y6X4N3Q8ZD5R2KT7VCPW", "entitlement.read")
    rejects(
        Codes.TOKEN_INVALID,
        lambda: verifier.verify_access_token(server.mint("srv-k1", "cli_other_client_00000000")),
    )
    # 모르는 kid — 1분 안에는 다시 받지 않는다
    rejects(Codes.TOKEN_INVALID, lambda: verifier.verify_access_token(server.mint("srv-k9", CLIENT_ID)))
    assert server.jwks_hits == 1
