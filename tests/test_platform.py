"""운영체제 포트 — 명령 · 파일을 기록하는 가짜로 명령 모양과 해석을 보고, 파일 저장소는 실제 디스크로 본다."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from keyring.errors import PasswordDeleteError

from bydev import CredentialRecord, Rules, platform
from bydev.platform import (
    ExitCodeError,
    _default_store,
    _DpapiStore,
    _FileStore,
    _OsFingerprint,
    _SecretToolStore,
)

RECORD = CredentialRecord(1, "rt_node_test_00000000001", "entitlement.read", "2026-10-06T13:00:00Z")
RECORD_JSON = '{"refreshToken":"rt_node_test_00000000001","savedAt":"2026-10-06T13:00:00Z","scope":"entitlement.read","version":1}'


class FakeOs:
    def __init__(self, name: str, answers: dict[str, str | Exception] | None = None) -> None:
        self.name = name
        self.answers = answers or {}
        self.calls: list[tuple[str, list[str], str | None]] = []
        self.files: dict[str, str] = {}
        self.tools: set[str] = set()

    def exec(self, program: str, args: list[str], stdin: str | None = None) -> str:
        self.calls.append((program, args, stdin))
        answer = self.answers.get(f"{program} {args[0]}", self.answers.get(program, ""))
        if isinstance(answer, Exception):
            raise answer
        return answer

    def has(self, program: str) -> bool:
        return program in self.tools

    def read_file(self, path: str) -> str | None:
        return self.files.get(path)

    def write_file(self, path: str, content: str) -> None:
        self.files[path] = content

    def remove(self, path: str) -> None:
        self.files.pop(path, None)

    def new_id(self) -> str:
        return "00000000-0000-4000-8000-00000000abcd"


class RecordingLog:
    def __init__(self) -> None:
        self.warns: list[str] = []

    def debug(self, message: str) -> None:
        pass

    def info(self, message: str) -> None:
        pass

    def warn(self, message: str) -> None:
        self.warns.append(message)


def test_fingerprint_per_os() -> None:
    win = FakeOs(
        "windows",
        {
            "reg": "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    3f1e9a2b-1111-2222-3333-444455556666\r\n"
        },
    )
    assert _OsFingerprint(None, win).read() == "3f1e9a2b-1111-2222-3333-444455556666"
    assert win.calls[0][1] == ["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"]
    mac = FakeOs("macos", {"ioreg": '  "IOPlatformUUID" = "A1B2C3D4-0000-1111-2222-333344445555"'})
    assert _OsFingerprint(None, mac).read() == "A1B2C3D4-0000-1111-2222-333344445555"
    linux = FakeOs("linux")
    linux.files["/var/lib/dbus/machine-id"] = "0123456789abcdef0123456789abcdef\n"
    assert _OsFingerprint(None, linux).read() == "0123456789abcdef0123456789abcdef"


def test_fingerprint_install_id_fallback() -> None:
    os_ = FakeOs("macos", {"ioreg": OSError("권한 없음")})
    source = _OsFingerprint("/app/install-id", os_)
    first = source.read()
    assert first == "00000000-0000-4000-8000-00000000abcd"
    assert os_.files["/app/install-id"] == first
    os_.files["/app/install-id"] = "kept-install-id\n"
    assert source.read() == "kept-install-id"
    # 파일 자리도 없으면 None(SDK가 수명 동안의 난수 ID로 물러난다)
    assert _OsFingerprint(None, os_).read() is None


def test_secret_tool_store() -> None:
    os_ = FakeOs("linux", {"secret-tool lookup": ExitCodeError("secret-tool", 1)})
    store = _SecretToolStore("cli_test", os_)
    assert store.load() is None  # 항목 없음
    store.save(RECORD)
    _, args, stdin = os_.calls[1]
    assert " ".join(args) == f"store --label=bydev cli_test service {Rules.STORAGE_SERVICE} account cli_test"
    # 비밀은 인자에 없고 표준 입력으로만
    assert not any(RECORD.refresh_token in a for a in args)
    assert stdin is not None and RECORD.refresh_token in stdin
    os_.answers = {"secret-tool lookup": RECORD_JSON}
    assert store.load() == RECORD
    # 다른 실패는 던진다 — SDK가 STORAGE_FAILED로 감싼다
    os_.answers = {"secret-tool lookup": ExitCodeError("secret-tool", 2)}
    with pytest.raises(ExitCodeError):
        store.load()
    # 없는 항목 지우기는 성공 — 오류 출력이 있으면(D-Bus 없음 등) 읽기 · 지우기 모두 던진다
    os_.answers = {"secret-tool clear": ExitCodeError("secret-tool", 1)}
    store.clear()
    broken = ExitCodeError("secret-tool", 1, "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n")
    os_.answers = {"secret-tool clear": broken, "secret-tool lookup": broken}
    with pytest.raises(ExitCodeError):
        store.clear()
    with pytest.raises(ExitCodeError):
        store.load()


def test_dpapi_store() -> None:
    os_ = FakeOs("windows", {"powershell.exe": "c2VhbGVk\r\n"})
    store = _DpapiStore("C:\\app\\bydev-credentials", os_)
    store.save(RECORD)
    assert os_.files["C:\\app\\bydev-credentials"] == "c2VhbGVk"
    _, args, stdin = os_.calls[0]
    assert args[:3] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert RECORD.refresh_token not in " ".join(args)
    assert stdin is not None and RECORD.refresh_token in stdin
    os_.answers = {"powershell.exe": RECORD_JSON}
    assert store.load() == RECORD
    assert os_.calls[1][2] == "c2VhbGVk"
    store.clear()
    assert store.load() is None


def test_file_store_real_disk(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "bydev-credentials"
    log = RecordingLog()
    store = platform.file_credential_store(str(path), log)
    assert len(log.warns) == 1  # 암호화하지 않는다는 warn
    assert store.load() is None
    store.save(RECORD)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert store.load() == RECORD
    # 판이 다른 기록은 없는 것으로 읽는다
    path.write_text('{"version":99,"refreshToken":"x"}')
    assert store.load() is None
    store.clear()
    store.clear()  # 없는 파일 지우기는 실패가 아니다
    assert list((tmp_path / "sub").iterdir()) == []  # 임시 파일이 남지 않는다


def test_default_store_choice() -> None:
    assert isinstance(_default_store("App", "cli", None, FakeOs("windows")), _DpapiStore)
    log = RecordingLog()
    assert isinstance(_default_store("App", "cli", log, FakeOs("linux")), _FileStore)  # secret-tool이 없으면
    assert len(log.warns) == 1
    linux = FakeOs("linux")
    linux.tools.add("secret-tool")
    assert isinstance(_default_store("App", "cli", None, linux), _SecretToolStore)
    assert isinstance(_default_store("App", "cli", None, FakeOs("macos")), _FileStore)
    assert platform.app_data_dir("App", _os="macos").endswith("Library/Application Support/App")


class FakeKeyring:
    """`keyring` 백엔드 모양(get · set · delete_password)."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.items.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.items[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if self.items.pop((service, username), None) is None:
            raise PasswordDeleteError("없음")


def test_keyring_store() -> None:
    backend = FakeKeyring()
    store = platform.keyring_credential_store("cli_test", backend)
    assert store.load() is None
    store.save(RECORD)
    assert backend.items[(Rules.STORAGE_SERVICE, "cli_test")] == RECORD_JSON
    assert store.load() == RECORD
    store.clear()
    store.clear()  # 없는 항목 지우기는 실패가 아니다
    assert store.load() is None


def test_fingerprint_this_machine() -> None:
    """이 기기의 실제 지문 출처를 한 번 읽는다(값은 출력하지 않는다)."""
    if platform._REAL.name == "other":
        pytest.skip("지원하지 않는 운영체제")
    value = platform.fingerprint_source().read()
    assert value, "이 기기의 지문 출처를 읽지 못했다"
    assert 1 <= len(platform.system_device_info().name) <= 64


@pytest.mark.skipif(
    os.environ.get("BYDEV_KEYCHAIN_CHECK") != "1",
    reason="사용자 키체인을 건드린다 — BYDEV_KEYCHAIN_CHECK=1일 때만 (launch-checklist A31)",
)
def test_real_keyring() -> None:
    """이 기기의 운영체제 보안 저장소(keyring이 고른 백엔드)에 실제로 넣고 · 고치고 · 읽고 · 지운다. 항목은 `bydev-keychain-check` 하나이고 끝나면 지운다."""
    store = platform.keyring_credential_store("bydev-keychain-check")
    store.clear()
    try:
        assert store.load() is None
        store.save(RECORD)
        assert store.load() == RECORD
        rotated = CredentialRecord(1, "rt_keychain_rotated_000001", RECORD.scope, RECORD.saved_at)
        store.save(rotated)
        assert store.load() == rotated
        store.clear()
        assert store.load() is None
    finally:
        store.clear()
