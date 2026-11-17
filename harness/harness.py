"""Python SDK의 적합성 하네스(sdks/spec/harness-protocol.md). 표준 입출력 JSON 줄로 실행기와 이야기하며 SDK를 가상 시계 · 가상 스케줄러 · 대리 전송으로 몬다.

블로킹 언어의 정착 판정: SDK 일을 하는 스레드 수(`running`)를 세고, 전송 · `sleep` · `wait`에서 기다리는 스레드는 그 기다림의 신호를 등록한다.
`running`이 0이고, 답을 기다리는 요청이 없고, 등록된 신호가 하나도 켜지지 않았으면(깨어날 스레드가 없으면) 할 일이 없다.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, NoReturn

from bydev import (
    SDK_VERSION,
    AppInfo,
    BydevError,
    Cancel,
    Config,
    CredentialRecord,
    DeviceInfo,
    HttpRequest,
    HttpResponse,
    LicenseClient,
    LoginAttempt,
    Ports,
    SessionState,
    Signal,
    Spec,
)
from bydev._support import parse_iso


@dataclass
class _Timer:
    due: int
    seq: int
    task: Callable[[], None]
    cancelled: bool = False


@dataclass
class _Exchange:
    done: Signal = field(default_factory=Signal)
    response: HttpResponse | None = None


@dataclass
class _State:
    """하네스 하나의 상태 — 잠금 `lock` 아래에서 읽고 쓴다(`out`은 출력 줄 순서)."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    out: threading.Lock = field(default_factory=threading.Lock)
    now: int = 0
    timers: list[_Timer] = field(default_factory=list)
    seq: int = 0
    running: int = 0
    waiters: dict[int, Signal] = field(default_factory=dict)
    waiter_id: int = 0
    pending: dict[str, _Exchange] = field(default_factory=dict)
    randoms: deque[float] = field(default_factory=deque)
    uuids: int = 0
    http_seq: int = 0
    record: CredentialRecord | None = None
    fail_load: bool = False
    fail_save: bool = False
    fail_clear: bool = False
    client: LicenseClient | None = None
    login: LoginAttempt | None = None


_H = _State()


def emit(message: dict[str, Any]) -> None:
    line = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    with _H.out:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def fatal(message: str) -> NoReturn:
    emit({"type": "fatal", "message": message})
    sys.stdout.flush()
    os._exit(1)


def clock() -> int:
    with _H.lock:
        return _H.now


def block(done: Signal) -> None:
    """SDK 스레드가 포트에서 기다리는 동안 `running`에서 빠지고 신호를 등록한다."""
    with _H.lock:
        _H.running -= 1
        _H.waiter_id += 1
        wid = _H.waiter_id
        _H.waiters[wid] = done
    done.block()
    with _H.lock:
        del _H.waiters[wid]
        _H.running += 1


def record_json(r: CredentialRecord) -> dict[str, Any]:
    return {"version": r.version, "refreshToken": r.refresh_token, "scope": r.scope, "savedAt": r.saved_at}


# ── 포트 ──────────────────────────────────────────────────────


class HarnessPorts:
    def __init__(self, fingerprint: str | None) -> None:
        self._fingerprint = fingerprint

    def now_ms(self) -> int:
        return clock()

    def after(self, delay_ms: int, task: Callable[[], None]) -> Cancel:
        with _H.lock:
            timer = _Timer(_H.now + max(0, delay_ms), _H.seq, task)
            _H.seq += 1
            _H.timers.append(timer)

        def cancel() -> None:
            with _H.lock:
                timer.cancelled = True

        return Cancel(cancel)

    def sleep(self, ms: int) -> None:
        done = Signal()
        self.after(ms, done.fire)
        block(done)

    def wait(self, signal: Signal) -> None:
        block(signal)

    def random(self) -> float:
        with _H.lock:
            value = _H.randoms.popleft() if _H.randoms else None
        if value is None:
            fatal("시나리오의 random 값을 다 썼다 — random에 더 적는다")
        return value

    def uuid(self) -> str:
        with _H.lock:
            _H.uuids += 1
            n = _H.uuids
        return f"00000000-0000-4000-8000-{n:012x}"

    def send(self, request: HttpRequest) -> HttpResponse:
        exchange = _Exchange()
        with _H.lock:
            _H.http_seq += 1
            hid = f"h{_H.http_seq}"
            _H.pending[hid] = exchange
            at = _H.now
        emit(
            {
                "type": "http.request",
                "id": hid,
                "now": at,
                "request": {
                    "method": request.method,
                    "url": request.url,
                    "headers": {k.lower(): v for k, v in request.headers.items()},
                    "body": request.body.decode() if request.body is not None else None,
                },
            }
        )
        block(exchange.done)
        with _H.lock:
            response = exchange.response
        if response is None:
            raise OSError("대리 전송 실패")
        return response

    def load(self) -> CredentialRecord | None:
        with _H.lock:
            if _H.fail_load:
                raise OSError("저장소 읽기 실패(시험)")
            return _H.record

    def save(self, record: CredentialRecord) -> None:
        with _H.lock:
            if _H.fail_save:
                raise OSError("저장소 쓰기 실패(시험)")
            _H.record = record
            at = _H.now
        emit(
            {
                "type": "event",
                "now": at,
                "event": {"kind": "storage", "op": "save", "record": record_json(record)},
            }
        )

    def clear(self) -> None:
        with _H.lock:
            if _H.fail_clear:
                raise OSError("저장소 지우기 실패(시험)")
            _H.record = None
            at = _H.now
        emit({"type": "event", "now": at, "event": {"kind": "storage", "op": "clear"}})

    def read(self) -> str | None:
        return self._fingerprint

    def debug(self, message: str) -> None:
        pass

    def info(self, message: str) -> None:
        pass

    def warn(self, message: str) -> None:
        print(f"warn: {message}", file=sys.stderr)


# ── 정착 ──────────────────────────────────────────────────────


def quiet() -> bool:
    with _H.lock:
        return _H.running == 0 and not _H.pending and not any(s.is_fired for s in _H.waiters.values())


def wait_quiet() -> None:
    while not quiet():
        time.sleep(0.00005)


def take_timer(limit: int) -> _Timer | None:
    """`limit`까지 온, 취소되지 않은 가장 이른 예약을 꺼낸다."""
    _H.timers = [t for t in _H.timers if not t.cancelled]
    due = [t for t in _H.timers if t.due <= limit]
    if not due:
        return None
    nxt = min(due, key=lambda t: (t.due, t.seq))
    _H.timers.remove(nxt)
    return nxt


def _run_timer(timer: _Timer) -> None:
    try:
        timer.task()
    finally:
        with _H.lock:
            _H.running -= 1


def settle() -> None:
    """지금 시각까지 온 예약 작업을 하나씩 — 앞 작업이 끝나거나 기다릴 때까지 — 돌린다."""
    while True:
        wait_quiet()
        with _H.lock:
            timer = take_timer(_H.now)
            if timer is None:
                return
            _H.running += 1
        threading.Thread(target=_run_timer, args=(timer,), daemon=True).start()


def advance(ms: int) -> None:
    target = clock() + ms
    while True:
        settle()
        with _H.lock:
            _H.timers = [t for t in _H.timers if not t.cancelled]
            due = [t.due for t in _H.timers if t.due <= target]
            if not due:
                break
            _H.now = min(due)
    with _H.lock:
        _H.now = target
    settle()


# ── 호출 ──────────────────────────────────────────────────────


def arg(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str):
        fatal(f"인자 {key}가 문자열이 아니다")
    return value


def invoke(method: str, args: dict[str, Any]) -> Any:
    with _H.lock:
        c = _H.client
    if c is None:
        fatal("init 전에 호출했다")
    match method:
        case "login.start":
            attempt = c.start_login()
            with _H.lock:
                _H.login = attempt
            return {
                "userCode": attempt.user_code,
                "verificationUri": attempt.verification_uri,
                "verificationUriComplete": attempt.verification_uri_complete,
                "expiresAt": attempt.expires_at,
            }
        case "login.wait":
            with _H.lock:
                login = _H.login
            if login is None:
                fatal("login.start 전에 login.wait")
            return login.wait().to_dict()
        case "login.cancel":
            with _H.lock:
                login = _H.login
            if login is not None:
                login.cancel()
            return None
        case "hasCredentials":
            return c.has_credentials()
        case "entitlement":
            return c.entitlement().to_dict()
        case "devices":
            limit = args.get("limit")
            return c.devices(
                args.get("cursor"), int(limit) if isinstance(limit, int | float) else None
            ).to_dict()
        case "releaseDevice":
            return c.release_device(arg(args, "deviceId")).to_dict()
        case "profile":
            return c.profile().to_dict()
        case "checkForUpdate":
            return c.check_for_update(arg(args, "target"), arg(args, "currentVersion")).to_dict()
        case "verifyDownload":
            c.verify_download(base64.b64decode(arg(args, "dataBase64")), arg(args, "sha256"))
            return None
        case "verifyToken":
            return c.verify_token(arg(args, "token")).to_dict()
        case "logout":
            return {"serverRevoked": c.logout()}
        case "session.start":
            c.session().start()
            return None
        case "session.takeOver":
            c.session().take_over()
            return None
        case "session.retry":
            c.session().retry()
            return None
        case "session.stop":
            c.session().stop()
            return None
        case "session.state":
            return c.session().state.to_dict()
        case _:
            fatal(f"모르는 호출 {method}")


def _call(cid: str, method: str, args: dict[str, Any]) -> None:
    message: dict[str, Any] = {"type": "result", "id": cid}
    try:
        message["ok"] = True
        message["value"] = invoke(method, args)
    except BydevError as e:
        message["ok"] = False
        message.pop("value", None)
        message["error"] = e.to_dict()
    except Exception as e:
        message["ok"] = False
        message.pop("value", None)
        message["error"] = {"code": "HARNESS_ERROR", "message": repr(e)}
    message["now"] = clock()
    emit(message)
    with _H.lock:
        _H.running -= 1


def start_call(cid: str, method: str, args: dict[str, Any]) -> None:
    with _H.lock:
        _H.running += 1
    threading.Thread(target=_call, args=(cid, method, args), daemon=True).start()


# ── 명령 ──────────────────────────────────────────────────────


def text(o: dict[str, Any], key: str) -> str:
    value = o.get(key)
    if not isinstance(value, str):
        fatal(f"init.{key}")
    return value


def initialize(message: dict[str, Any]) -> None:
    config = message.get("config")
    device = config.get("device") if isinstance(config, dict) else None
    if not isinstance(config, dict) or not isinstance(device, dict):
        fatal("init.config")
    started = parse_iso(message.get("now") or "")
    if started is None:
        fatal("init.now")
    with _H.lock:
        _H.now = started
        _H.randoms.extend(float(v) for v in message.get("random") or [] if isinstance(v, int | float))
        storage = message.get("storage")
        if isinstance(storage, dict) and isinstance(storage.get("refreshToken"), str):
            _H.record = CredentialRecord(
                int(storage.get("version", 1)),
                storage["refreshToken"],
                storage.get("scope") or "",
                storage.get("savedAt") or "",
            )
    raw_app = config.get("app")
    app = None
    if raw_app is not None:
        if not isinstance(raw_app, dict):
            fatal("init.config.app")
        app = AppInfo(text(raw_app, "target"), text(raw_app, "version"))
    ports = HarnessPorts(device.get("fingerprintSource"))
    try:
        client = LicenseClient(
            Config(
                base_url=text(config, "baseUrl"),
                client_id=text(config, "clientId"),
                product_id=text(config, "productId"),
                scopes=[s for s in config.get("scopes") or [] if isinstance(s, str)],
                device=DeviceInfo(text(device, "name"), text(device, "platform")),
                ports=Ports(
                    transport=ports,
                    store=ports,
                    clock=ports,
                    scheduler=ports,
                    random=ports,
                    fingerprint=ports,
                    logger=ports,
                ),
                app=app,
            )
        )
    except BydevError as e:
        fatal(f"LicenseClient: {e}")

    def on_state(state: SessionState) -> None:
        emit({"type": "event", "now": clock(), "event": {"kind": "session.state", "state": state.to_dict()}})

    client.session().subscribe(on_state)
    with _H.lock:
        _H.client = client


def on_http_response(message: dict[str, Any]) -> None:
    hid = message.get("id") or ""
    # 지우기와 켜기를 한 잠금 안에서 — 둘 사이에 "할 일 없음"으로 보이는 틈이 없게
    with _H.lock:
        exchange = _H.pending.pop(hid, None)
        if exchange is not None:
            r = message.get("response")
            if isinstance(r, dict):
                headers = r.get("headers") or {}
                exchange.response = HttpResponse(
                    int(r.get("status") or 0),
                    {k.lower(): v if isinstance(v, str) else "" for k, v in headers.items()},
                    (r.get("body") or "").encode(),
                )
            exchange.done.fire()
    if exchange is None:
        fatal(f"모르는 http.response id {hid}")


def main() -> None:
    sys.stdin.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    emit({"type": "ready", "sdk": "python", "version": SDK_VERSION, "specVersion": Spec.VERSION})
    inbox: queue.Queue[dict[str, Any]] = queue.Queue()

    def reader() -> None:
        for line in sys.stdin:
            try:
                message = json.loads(line)
            except ValueError:
                fatal(f"JSON이 아닌 입력: {line}")
            if not isinstance(message, dict):
                fatal(f"JSON이 아닌 입력: {line}")
            if message.get("type") == "http.response":
                on_http_response(message)
            else:
                inbox.put(message)
        inbox.put({"type": "end"})

    threading.Thread(target=reader, daemon=True).start()
    while True:
        message = inbox.get()
        match message.get("type") or "":
            case "init":
                initialize(message)
                settle()
            case "call":
                for call in message.get("calls") or []:
                    if isinstance(call, dict):
                        start_call(call.get("id") or "", call.get("method") or "", call.get("args") or {})
                settle()
            case "advance":
                advance(int(message.get("ms") or 0))
            case "set":
                value = message.get("value") is True
                with _H.lock:
                    match message.get("key"):
                        case "storage.failLoad":
                            _H.fail_load = value
                        case "storage.failSave":
                            _H.fail_save = value
                        case "storage.failClear":
                            _H.fail_clear = value
                settle()
            case "end":
                sys.stdout.flush()
                os._exit(0)
            case other:
                fatal(f"모르는 명령 {other}")
        emit({"type": "idle", "now": clock()})


if __name__ == "__main__":
    main()
