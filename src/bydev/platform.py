"""명세 2절 표 — 운영체제별 기본 구현. 원본 지문 · 토큰을 명령 줄 인자로 넘기지 않는다(비밀은 표준 입력으로만).

TS · Go · Kotlin과 같은 명령 모양이다. 클라이언트의 기본 저장소는 메모리다 — 앱이 이 중에서 고른다.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Protocol

from ._generated import DevicePlatform, Rules
from ._support import dumps, loads
from .ports import CredentialRecord, CredentialStore, FingerprintSource, LogSink
from .session import DeviceInfo

# Windows에서 명령(powershell · reg)을 콘솔 창 없이 띄운다(CREATE_NO_WINDOW). GUI 앱(pythonw · 묶은 실행 파일)이 띄운 콘솔 명령은 창이 깜빡이고,
# 콘솔을 만들지 못하면 0xC0000142로 끝난다(명세 2절). 다른 운영체제는 0
_NO_CONSOLE = 0x08000000 if sys.platform == "win32" else 0


class ExitCodeError(OSError):
    """명령이 0이 아닌 코드로 끝났다. ``stderr``는 그 명령의 오류 출력이다."""

    def __init__(self, program: str, code: int, stderr: str = "") -> None:
        super().__init__(f"{program}가 {code}로 끝났다")
        self.code = code
        self.stderr = stderr


class _Os(Protocol):
    """명령 실행 · 파일 — 단위 시험이 바꿔 끼운다."""

    name: str

    def exec(self, program: str, args: list[str], stdin: str | None = None) -> str: ...

    def has(self, program: str) -> bool: ...

    def read_file(self, path: str) -> str | None: ...

    def write_file(self, path: str, content: str) -> None: ...

    def remove(self, path: str) -> None: ...

    def new_id(self) -> str: ...

    def sleep(self, seconds: float) -> None: ...

    def machine_guid(self) -> str | None:
        """Windows 레지스트리 API로 읽은 MachineGuid — 읽지 못하면 None(그때는 reg 명령으로)."""
        ...


def _os_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return "other"


class _RealOs:
    name = _os_name()

    def exec(self, program: str, args: list[str], stdin: str | None = None) -> str:
        # 고정된 프로그램 · 인자 — 비밀은 표준 입력으로만
        done = subprocess.run(
            [program, *args],
            input=(stdin or "").encode(),
            # 오류 출력도 받아 실어 보낸다 — secret-tool은 "항목 없음"과 오류를 같은 종료 코드(1)로 내고 오류 출력으로만 가른다
            capture_output=True,
            check=False,
            creationflags=_NO_CONSOLE,
        )
        if done.returncode != 0:
            raise ExitCodeError(program, done.returncode, done.stderr.decode(errors="replace"))
        return done.stdout.decode()

    def has(self, program: str) -> bool:
        return shutil.which(program) is not None

    def read_file(self, path: str) -> str | None:
        try:
            return Path(path).read_text(encoding="utf-8")
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None

    def write_file(self, path: str, content: str) -> None:
        """사용자만 읽는 권한(0600) 임시 파일 뒤 이름 바꾸기 — 반쯤 쓴 파일이 남지 않게, 다른 사용자가 읽는 틈이 없게."""
        target = Path(path).absolute()
        target.parent.mkdir(parents=True, exist_ok=True)
        # mkstemp는 0600으로 만든다(POSIX)
        fd, temp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(temp, target)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp)

    def remove(self, path: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

    def new_id(self) -> str:
        return str(uuid.uuid4())

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def machine_guid(self) -> str | None:
        """명령을 띄우지 않고 표준 라이브러리 winreg로 읽는다(명세 10절) — 32비트 Python도 64비트 보기를 읽는다(KEY_WOW64_64KEY)."""
        if sys.platform != "win32":
            return None
        import winreg  # Windows에만 있다

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                value, kind = winreg.QueryValueEx(key, "MachineGuid")
        except OSError:
            return None
        return value if kind == winreg.REG_SZ and isinstance(value, str) else None


_REAL = _RealOs()


def app_data_dir(app_name: str, *, _os: str | None = None) -> str:
    """운영체제 · 앱 이름별 데이터 폴더다."""
    home = Path.home()
    match _os or _REAL.name:
        case "windows":
            return str(Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming") / app_name)
        case "macos":
            return str(home / "Library" / "Application Support" / app_name)
        case _:
            return str(Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") / app_name)


def system_device_info() -> DeviceInfo:
    """`Config.device`의 기본값 — 컴퓨터 이름(64자까지)과 운영체제."""
    platform = {
        "windows": DevicePlatform.WINDOWS,
        "macos": DevicePlatform.MACOS,
        "linux": DevicePlatform.LINUX,
    }.get(_REAL.name, DevicePlatform.OTHER)
    name = (os.environ.get("COMPUTERNAME") or socket.gethostname() or "").strip() or "PC"
    return DeviceInfo(name[:64], platform)


_MACHINE_GUID = re.compile(r"MachineGuid\s+REG_SZ\s+(\S+)")
_PLATFORM_UUID = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')


class _OsFingerprint:
    def __init__(self, install_id_file: str | None, os_: _Os) -> None:
        self._file = install_id_file
        self._os = os_

    def read(self) -> str | None:
        # 실패하거나 빈 값이면 설치 ID로 물러나기 전에 다시 읽는다(명세 10절) — 일시적인 실패 하나로 같은 PC가 다른 기기가 되지 않게
        for attempt in range(max(Rules.FINGERPRINT_SOURCE_READ_ATTEMPTS, 1)):
            if attempt > 0:
                self._os.sleep(Rules.FINGERPRINT_SOURCE_READ_RETRY_DELAY_MS / 1000)
            try:
                machine = (self._machine_id() or "").strip()
            except OSError:
                machine = ""
            if machine:
                return machine
        if self._file is None:
            return None
        saved = (self._os.read_file(self._file) or "").strip()
        if saved:
            return saved
        fresh = self._os.new_id()
        self._os.write_file(self._file, fresh)
        return fresh

    def _machine_id(self) -> str | None:
        match self._os.name:
            case "windows":
                api = (
                    self._os.machine_guid() or ""
                ).strip()  # 레지스트리 API가 먼저 — 프로세스를 띄우지 않는다
                if api:
                    return api
                out = self._os.exec(
                    "reg", ["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"]
                )
                m = _MACHINE_GUID.search(out)
                return m.group(1) if m else None
            case "macos":
                m = _PLATFORM_UUID.search(self._os.exec("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"]))
                return m.group(1) if m else None
            case _:
                first = self._os.read_file("/etc/machine-id")
                return first if first and first.strip() else self._os.read_file("/var/lib/dbus/machine-id")


def fingerprint_source(install_id_file: str | None = None) -> FingerprintSource:
    """명세 10절 · 2절 표의 지문 출처 — Windows MachineGuid · macOS IOPlatformUUID · Linux /etc/machine-id.

    읽지 못하면 `install_id_file`의 설치 ID(없으면 만든다). `install_id_file`이 None이면 None(SDK가 클라이언트 수명 동안의 난수 ID로 물러난다).
    """
    return _OsFingerprint(install_id_file, _REAL)


def _parse_record(text: str | None) -> CredentialRecord | None:
    o = loads(text) if text else None
    if not isinstance(o, dict) or o.get("version") != Rules.STORAGE_RECORD_VERSION:
        return None
    token = o.get("refreshToken")
    if not isinstance(token, str) or not token:
        return None
    scope, saved_at = o.get("scope"), o.get("savedAt")
    return CredentialRecord(
        1, token, scope if isinstance(scope, str) else "", saved_at if isinstance(saved_at, str) else ""
    )


def _write_record(r: CredentialRecord) -> str:
    return dumps(
        {"version": r.version, "refreshToken": r.refresh_token, "scope": r.scope, "savedAt": r.saved_at}
    )


class _FileStore:
    def __init__(self, path: str, logger: LogSink | None, os_: _Os) -> None:
        self._path = path
        self._os = os_
        if logger is not None:
            logger.warn(
                "로그인 기록을 암호화하지 않은 사용자 전용 파일에 둔다 — 운영체제 보안 저장소를 쓸 수 없는 환경"
            )

    def load(self) -> CredentialRecord | None:
        return _parse_record(self._os.read_file(self._path))

    def save(self, record: CredentialRecord) -> None:
        self._os.write_file(self._path, _write_record(record))

    def clear(self) -> None:
        self._os.remove(self._path)


def _secret_tool_found_nothing(error: ExitCodeError) -> bool:
    """secret-tool이 항목을 찾지 못했다 — 오류 출력 없이 1로 끝난다.

    오류(D-Bus 없음 · 잠긴 모음 · 없는 모음)도 1이지만 ``secret-tool: …``를 쓴다(2026-10-17 Debian 12 libsecret 0.20에서 확인).
    """
    return error.code == 1 and error.stderr.strip() == ""


class _SecretToolStore:
    def __init__(self, account: str, os_: _Os) -> None:
        self._account = account
        self._os = os_

    def _attributes(self, verb: str, *extra: str) -> list[str]:
        return [verb, *extra, "service", Rules.STORAGE_SERVICE, "account", self._account]

    def load(self) -> CredentialRecord | None:
        try:
            return _parse_record(self._os.exec("secret-tool", self._attributes("lookup")))
        except ExitCodeError as e:
            if _secret_tool_found_nothing(e):
                return None
            raise

    def save(self, record: CredentialRecord) -> None:
        self._os.exec(
            "secret-tool", self._attributes("store", f"--label=bydev {self._account}"), _write_record(record)
        )

    def clear(self) -> None:
        # 없는 항목을 지우는 것은 성공이다(로그아웃은 몇 번 해도 된다)
        try:
            self._os.exec("secret-tool", self._attributes("clear"))
        except ExitCodeError as e:
            if not _secret_tool_found_nothing(e):
                raise


_PROTECT = (
    "Add-Type -AssemblyName System.Security; $b=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd()); "
    "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))"
)
_UNPROTECT = (
    "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); "
    "[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))"
)


class _DpapiStore:
    def __init__(self, path: str, os_: _Os) -> None:
        self._path = path
        self._os = os_

    def _ps(self, script: str, data: str) -> str:
        return self._os.exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], data)

    def load(self) -> CredentialRecord | None:
        sealed = (self._os.read_file(self._path) or "").strip()
        return _parse_record(self._ps(_UNPROTECT, sealed)) if sealed else None

    def save(self, record: CredentialRecord) -> None:
        self._os.write_file(self._path, self._ps(_PROTECT, _write_record(record)).strip())

    def clear(self) -> None:
        self._os.remove(self._path)


def file_credential_store(path: str, logger: LogSink | None = None) -> CredentialStore:
    """사용자 전용 권한(0600) 파일 — **암호화하지 않는다.** 운영체제 보안 저장소를 쓸 수 없을 때만(warn 로그)."""
    return _FileStore(path, logger, _REAL)


def dpapi_credential_store(path: str) -> CredentialStore:
    """Windows DPAPI(현재 사용자 범위)로 봉한 파일 — PowerShell에 표준 입력으로 넘긴다."""
    return _DpapiStore(path, _REAL)


def secret_tool_credential_store(account: str) -> CredentialStore:
    """Linux Secret Service(libsecret `secret-tool`) — 비밀은 표준 입력으로 넘긴다. account는 client_id."""
    return _SecretToolStore(account, _REAL)


def _default_store(app_name: str, account: str, logger: LogSink | None, os_: _Os) -> CredentialStore:
    file = str(Path(app_data_dir(app_name, _os=os_.name)) / "bydev-credentials")
    if os_.name == "windows":
        return _DpapiStore(file, os_)
    if os_.name == "linux" and os_.has("secret-tool"):
        return _SecretToolStore(account, os_)
    return _FileStore(file, logger, os_)


def default_credential_store(app_name: str, account: str, logger: LogSink | None = None) -> CredentialStore:
    """운영체제에 맞는 기본 저장소 — Windows DPAPI 파일 · Linux Secret Service(`secret-tool`이 없으면 0600 파일 + warn) · macOS는 0600 파일 + warn.

    macOS 키체인은 `keyring` 추가 설치(`bydev[keyring]`)의 `keyring_credential_store`로 쓴다 — `security` 명령은 비밀을 인자로 받아 쓰지 않는다
    (ADR-0040 ⚠ 10). account는 client_id.
    """
    return _default_store(app_name, account, logger, _REAL)


class _KeyringStore:
    def __init__(self, account: str, backend: Any) -> None:
        self._account = account
        self._backend = backend

    def load(self) -> CredentialRecord | None:
        return _parse_record(self._backend.get_password(Rules.STORAGE_SERVICE, self._account))

    def save(self, record: CredentialRecord) -> None:
        self._backend.set_password(Rules.STORAGE_SERVICE, self._account, _write_record(record))

    def clear(self) -> None:
        # 없는 항목을 지우면 백엔드가 던진다 — 지워진 것과 같다
        with contextlib.suppress(*_keyring_errors()):
            self._backend.delete_password(Rules.STORAGE_SERVICE, self._account)


def _keyring_errors() -> tuple[type[BaseException], ...]:
    try:
        from keyring.errors import PasswordDeleteError
    except ImportError:
        return (LookupError,)
    return (PasswordDeleteError, LookupError)


def keyring_credential_store(account: str, backend: Any = None) -> CredentialStore:
    """`keyring` 라이브러리의 저장소 — macOS 키체인 · Windows 자격 증명 관리자 · Secret Service. `pip install "bydev[keyring]"`로 깐다.

    `backend`를 주면 그 백엔드(`keyring.backend.KeyringBackend`)를, 아니면 `keyring`이 고른 기본 백엔드를 쓴다. account는 client_id.
    """
    if backend is None:
        try:
            import keyring
        except ImportError as e:
            raise ImportError(
                'keyring_credential_store에는 keyring이 필요하다 — pip install "bydev[keyring]"'
            ) from e
        backend = keyring.get_keyring()
    return _KeyringStore(account, backend)
