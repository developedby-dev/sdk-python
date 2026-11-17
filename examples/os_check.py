"""운영체제 포트 실제 확인 — Windows · Linux 기기에서 돌린다(launch-checklist A31 · ADR-0040).

사용자 보안 저장소를 건드리므로 ``BYDEV_KEYCHAIN_CHECK=1``일 때만 — ``BYDEV_KEYCHAIN_CHECK=1 python examples/os_check.py``.
기본 저장소(``default_credential_store`` — Windows DPAPI 파일 · Linux Secret Service)에 항목 하나(계정 ``bydev-keychain-check``)를 넣고 · 고치고 ·
읽고 · 지운다. 보안 저장소 대신 0600 파일로 떨어지면(경고 로그) 실패다. 지문 출처(``fingerprint_source`` — MachineGuid · machine-id)가 설치 ID
파일 없이 운영체제 값을 읽고 두 번 읽어도 같은지 본다.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from bydev import CredentialRecord
from bydev.platform import (
    app_data_dir,
    default_credential_store,
    fingerprint_source,
    system_device_info,
)

APP = "bydev-os-check"
ACCOUNT = "bydev-keychain-check"


class _Warnings:
    def __init__(self) -> None:
        self.seen: list[str] = []

    def debug(self, message: str) -> None:
        pass

    def info(self, message: str) -> None:
        pass

    def warn(self, message: str) -> None:
        self.seen.append(message)


def main() -> int:
    # 결과 줄의 ✓ · — 는 Windows ANSI 코드 페이지(한국어는 CP949)에 없다 — 출력이 파이프로 나가도 UTF-8로 쓴다
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    if os.environ.get("BYDEV_KEYCHAIN_CHECK") != "1":
        print("BYDEV_KEYCHAIN_CHECK=1이 아니라 건너뛴다 — 사용자 보안 저장소를 건드린다")
        return 0
    if sys.platform not in ("linux", "win32"):
        print(f"{sys.platform}는 대상이 아니다 — Windows · Linux에서 돌린다")
        return 0
    failures: list[str] = []
    device = system_device_info()
    print(f"기기 {device.name} · {device.platform}")

    source = fingerprint_source()
    first, again = source.read(), source.read()
    if first is None:
        failures.append("지문 — 운영체제 값을 읽지 못했다(설치 ID 없이)")
    elif first != again:
        failures.append("지문 — 두 번 읽은 값이 다르다")
    else:
        print(f"✓ 지문 출처 — 운영체제 값(길이 {len(first)})을 읽었고 두 번 같다")

    logger = _Warnings()
    store = default_credential_store(APP, ACCOUNT, logger)
    record = CredentialRecord(
        version=1,
        refresh_token="rt_node_test_00000000001",
        scope="entitlement.read",
        saved_at="2026-10-06T13:00:00Z",
    )
    rotated = dataclasses.replace(record, refresh_token="rt_keychain_rotated_000001")
    try:
        store.clear()
        if store.load() is not None:
            failures.append("저장소 — 지운 뒤에도 항목이 있다")
        for want in (record, rotated):
            store.save(want)
            if store.load() != want:
                failures.append("저장소 — 넣은 것을 읽지 못했다")
        store.clear()
        if store.load() is not None:
            failures.append("저장소 — 지운 항목이 남았다")
        if logger.seen:
            failures.append(f"저장소 — 보안 저장소가 아니라 파일로 떨어졌다: {' / '.join(logger.seen)}")
        elif not any(f.startswith("저장소") for f in failures):
            kind = "DPAPI 파일" if sys.platform == "win32" else "Secret Service"
            print(f"✓ 기본 저장소({kind}) — 넣기 · 고치기 · 읽기 · 지우기")
    except Exception as error:
        failures.append(f"저장소 — {error!r}")
    finally:
        with contextlib.suppress(Exception):
            store.clear()
        shutil.rmtree(app_data_dir(APP), ignore_errors=True)
    for failure in failures:
        print(f"✗ {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
