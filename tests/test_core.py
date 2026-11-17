"""에러 분류 · JSON · 시각 · 응답 읽기 — 순수 도우미."""

from __future__ import annotations

import pytest

from bydev import (
    BydevError,
    Codes,
    Entitlement,
    LicenseClaims,
    Profile,
    UpdateCheck,
    UpdateCoverage,
    UpdateCoverageType,
)
from bydev._support import dumps, format_iso, loads, parse_iso


@pytest.mark.parametrize(
    ("code", "status", "want"),
    [
        ("RATE_LIMITED", 429, True),
        ("INTERNAL_ERROR", 503, True),
        ("NETWORK_ERROR", None, True),
        # 429인 한도 초과 코드는 끝난 실패다
        ("TAKEOVER_LIMIT_EXCEEDED", 429, False),
        ("DEVICE_RELEASE_LIMIT_EXCEEDED", 429, False),
        # 모르는 코드만 HTTP 상태로
        ("FUTURE_THROTTLE", 429, True),
        ("FUTURE_OUTAGE", 502, True),
        ("FUTURE_FORBIDDEN", 403, False),
        ("FUTURE_NOTHING", None, False),
        ("STORAGE_FAILED", None, False),
    ],
)
def test_transient(code: str, status: int | None, want: bool) -> None:
    """명세 3.4 — 일시적 실패 분류."""
    assert BydevError(code, "시험", http_status=status).is_transient is want


def test_error_json_has_every_key() -> None:
    """키는 언제나 다 있다 — 없는 값은 None."""
    e = BydevError(
        Codes.RATE_LIMITED, "잠시 뒤에", http_status=429, correlation_id="req_err0001", retry_after_sec=30
    )
    assert (
        dumps(e.to_dict())
        == '{"code":"RATE_LIMITED","correlationId":"req_err0001","details":null,"httpStatus":429,"message":"잠시 뒤에","retryAfterSec":30}'
    )
    assert str(e) == "RATE_LIMITED: 잠시 뒤에"


def test_json_reads_strictly() -> None:
    v = loads('{"a":[1,2.5,-3e2,true,null],"s":"줄\\n\\"\\\\\\u00e9\\ud83d\\ude00","o":{}}')
    assert v == {"a": [1, 2.5, -300.0, True, None], "s": '줄\n"\\é😀', "o": {}}
    assert dumps(v) == '{"a":[1,2.5,-300.0,true,null],"o":{},"s":"줄\\n\\"\\\\é😀"}'
    for bad in ["", "{", "[1,]", '{"a" 1}', "01", "nul", "1 2", "NaN", "[Infinity]"]:
        assert loads(bad) is None, bad


def test_iso_time_round_trip() -> None:
    assert parse_iso("2026-10-06T13:00:00Z") == 1_791_291_600_000
    assert format_iso(1_791_291_600_000) == "2026-10-06T13:00:00Z"
    assert format_iso(1_791_291_600_250) == "2026-10-06T13:00:00.250Z"
    assert parse_iso("2026-10-06T22:00:00.5+09:00") == 1_791_291_600_500
    assert parse_iso("1970-01-01T00:00:00Z") == 0
    assert format_iso(951_782_400_000) == "2000-02-29T00:00:00Z"
    assert parse_iso("2026-10-06 13:00:00Z") is None
    assert parse_iso("2026-10-06T13:00:00") is None


def test_lenient_but_strict_reading() -> None:
    """빠진 필드 · 틀린 형은 PROTOCOL_ERROR — 모르는 필드는 버린다."""
    ok = Profile.read(loads('{"profile":{"pseudonymousId":"psub_1","nickname":"코드장인","extra":1}}'))
    assert ok == Profile("psub_1", "코드장인", None)
    assert ok.to_dict() == {"pseudonymousId": "psub_1", "nickname": "코드장인", "email": None}
    with pytest.raises(BydevError) as caught:
        Profile.read(loads('{"profile":{"nickname":"코드장인"}}'))
    assert caught.value.code == Codes.PROTOCOL_ERROR
    assert "profile.pseudonymousId" in caught.value.message


def _entitlement(coverage: str | None) -> str:
    extra = "" if coverage is None else f',"updateCoverage":{coverage}'
    return (
        '{"entitlement":{"id":"ent_1","productId":"prod_1","status":"ACTIVE",'
        '"term":{"type":"PERPETUAL","expiresAt":null,"remainingDays":null,"remainingSeconds":null}'
        f'{extra},"subscription":null,'
        '"policy":{"maxDevices":3,"maxConcurrent":1,"heartbeatSec":150,"offlineGraceHours":0},'
        '"evaluatedAt":"2026-10-06T14:00:00Z"}}'
    )


def test_update_coverage_reading() -> None:
    """ADR-0049 — 모르는 `type`은 원래 문자열만 남기고, 빠지면 다른 필수 필드처럼 PROTOCOL_ERROR."""
    until = Entitlement.read(loads(_entitlement('{"type":"UNTIL","until":"2027-11-12T03:00:00Z"}')))
    assert until.update_coverage == UpdateCoverage(UpdateCoverageType.UNTIL, "2027-11-12T03:00:00Z")
    unknown = Entitlement.read(loads(_entitlement('{"type":"BY_RELEASE_LINE","line":"2.x"}')))
    assert unknown.update_coverage.to_dict() == {"type": "BY_RELEASE_LINE"}
    with pytest.raises(BydevError) as caught:
        Entitlement.read(loads(_entitlement(None)))
    assert caught.value.code == Codes.PROTOCOL_ERROR
    assert "entitlement.updateCoverage" in caught.value.message
    with pytest.raises(BydevError) as caught:
        Entitlement.read(loads(_entitlement('{"type":"UNTIL"}')))
    assert "entitlement.updateCoverage.until" in caught.value.message


def test_optional_entitled_and_build_id() -> None:
    """`entitled` · `build_id`는 없으면 None이고 `to_dict()`에서도 빠진다(계약 모양)."""
    body = (
        '{"product":{"id":"prod_1"},"target":"WINDOWS_X64",'
        '"latest":{"version":"2.0.0","releasedAt":"2027-12-01T06:00:00Z","notes":null},'
        '"update":{"status":"AVAILABLE"},"install":{"mode":"SIDELOAD"}'
    )
    plain = UpdateCheck.read(loads(body + "}"))
    assert plain.entitled is None
    assert "entitled" not in plain.to_dict()
    empty = UpdateCheck.read(
        loads(body + ',"entitled":{"coveredUntil":"2027-11-12T03:00:00Z","release":null}}')
    )
    assert empty.entitled is not None and empty.entitled.release is None
    with pytest.raises(BydevError) as caught:
        UpdateCheck.read(
            loads(body + ',"entitled":{"coveredUntil":"2027-11-12T03:00:00Z","release":{"latest":{}}}}')
        )
    assert "entitled.release.latest.version" in caught.value.message
    claims = {
        "iss": "https://api.example.test",
        "sub": "psub_1",
        "aud": "cli_1",
        "product_id": "prod_1",
        "device_id": "dev_1",
        "sid": "sess_1",
        "generation": 1,
        "iat": 1,
        "exp": 2,
    }
    assert LicenseClaims.read(claims).build_id is None
    assert "build_id" not in LicenseClaims.read(claims).to_dict()
    assert LicenseClaims.read({**claims, "build_id": "build_1"}).to_dict()["build_id"] == "build_1"
