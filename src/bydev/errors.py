"""SDK의 에러 하나(명세 3.3)."""

from __future__ import annotations

from typing import Any

from ._generated import Codes, Rules


class BydevError(Exception):
    """`code`로 분기하고(생성된 `Codes`) `message`는 보여 주기만 한다. 앱의 오류 화면에 `correlation_id`를 보이면 문의를 바로 찾는다."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        http_status: int | None = None,
        correlation_id: str | None = None,
        retry_after_sec: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.correlation_id = correlation_id
        self.retry_after_sec = retry_after_sec
        self.details = details

    @property
    def is_transient(self) -> bool:
        """일시적 실패인지다(명세 3.4). 아는 코드는 그 뜻대로 — 429인 한도 초과 코드는 끝난 실패 — 모르는 코드만 HTTP 상태로 나눈다."""
        if self.code in Rules.TRANSIENT_CODES:
            return True
        if self.code in Codes.API_HTTP_STATUS or self.code in Codes.SDK:
            return False
        status = self.http_status
        if status is None:
            return False
        return status in Rules.TRANSIENT_UNKNOWN_CODE_STATUSES or any(
            lo <= status <= hi for lo, hi in Rules.TRANSIENT_UNKNOWN_CODE_STATUS_RANGES
        )

    def to_dict(self) -> dict[str, Any]:
        """`{"code","message","httpStatus","correlationId","retryAfterSec","details"}` — 키는 언제나 다 있다(없는 값은 None)."""
        return {
            "code": self.code,
            "message": self.message,
            "httpStatus": self.http_status,
            "correlationId": self.correlation_id,
            "retryAfterSec": self.retry_after_sec,
            "details": self.details,
        }

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def __repr__(self) -> str:
        return f"BydevError({self.code!r}, {self.message!r})"


def wrap(error: BaseException, code: str, message: str) -> BydevError:
    """포트가 던진 에러를 `code`로 감싼다 — 이미 `BydevError`면 그대로."""
    if isinstance(error, BydevError):
        return error
    wrapped = BydevError(code, message)
    wrapped.__cause__ = error
    return wrapped


def storage(error: BaseException, message: str) -> BydevError:
    """저장소 실패는 언제나 `STORAGE_FAILED`(명세 2절)."""
    if isinstance(error, BydevError) and error.code == Codes.STORAGE_FAILED:
        return error
    wrapped = BydevError(Codes.STORAGE_FAILED, message)
    wrapped.__cause__ = error
    return wrapped
