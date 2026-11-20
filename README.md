# 데브 SDK: Python

데브 라이선스 API의 공식 Python SDK입니다. PySide, Tkinter, wxPython으로 만든 데스크톱 앱과 판매자 서버에서 씁니다.

의존성은 Ed25519 처리에 쓰는
`cryptography` 하나뿐입니다. HTTP는 표준 `urllib`, JSON은 표준 `json`으로 처리합니다.

모든 언어의 SDK가 함께 따르는 [공통 동작 명세](https://github.com/developedby-dev/sdk-spec/blob/main/spec/README.md)대로
동작하고, [적합성 시험 시나리오](https://github.com/developedby-dev/sdk-spec/tree/main/conformance/scenarios)를 모두 통과합니다.

| 지원 | 버전 |
|---|---|
| 동작 명세 | 1.2.0 |
| API | v1 |
| Python | 3.11 이상 |
| 운영체제 | Windows, macOS, Linux |

패키지 이름은 `bydev`입니다. 지금 PyPI에 있는 0.x 판은 이름을 먼저 등록하려고 낸 미리보기입니다. 1.0.0은 서비스 오픈과 함께 내며, 그 전에는
호환되지 않는 변경이 있을 수 있습니다. 판매하는 앱에는 1.0.0 이상을 써 주세요.

## 빠른 시작

이 SDK는 **블로킹 API**입니다. UI 스레드에서 부르지 말고 작업 스레드에서 호출해 주세요.

asyncio 앱에서는 `bydev.aio.AsyncLicenseClient`를 쓰면 됩니다.
같은 클라이언트를 `asyncio.to_thread`로 감싼 것입니다.

```python
from bydev import Active, AppInfo, Config, Degraded, LicenseClient, Locked, NeedsDecision, Ports, Scope
from bydev import platform

client_id = "cli_01J9M0Y6X4N3Q8ZD5R2KT7VCPW"  # 판매자 콘솔에서 제품마다 발급받습니다
client = LicenseClient(
    Config(
        base_url="https://api.developedby.dev",
        client_id=client_id,
        product_id="prod_01J9KZ3F7W2X8YQ4N6M5R1TBCD",
        scopes=[Scope.ENTITLEMENT_READ, Scope.SESSION_WRITE, Scope.VERSION_READ],
        device=platform.system_device_info(),
        app=AppInfo(target="WINDOWS_X64", version="1.4.0"),  # 콘솔에 업로드한 빌드의 버전과 같게
        ports=Ports(
            store=platform.default_credential_store("MyApp", client_id, logger),
            fingerprint=platform.fingerprint_source(f"{platform.app_data_dir('MyApp')}/install-id"),
        ),
    )
)

if not client.has_credentials():
    login = client.start_login()
    show_code(login.user_code, login.verification_uri_complete)  # 화면에 코드와 QR 코드를 보여 줍니다
    login.wait()  # 사용자가 브라우저에서 승인할 때까지 기다립니다. 취소는 login.cancel()로 합니다

session = client.session()


def on_state(state):  # SDK의 스레드에서 불리므로, UI 작업은 UI 스레드로 넘기세요
    match state:
        # Degraded여도 offline_until까지는 계속 쓸 수 있습니다
        case Active(claims=claims) | Degraded(claims=claims):
            enable_features(claims)  # exp와 sid는 기능 코드에서 쓰고, 참/거짓 하나로만 판단하지 마세요
        case NeedsDecision():
            ask_user(state)  # DEVICE_IN_USE: "여기서 사용할까요?"에 동의하면 session.take_over()를 부릅니다
        case Locked(code=code, correlation_id=cid):
            lock_app(code, cid)  # 오류 화면에 correlation_id를 보여 주세요


subscription = session.subscribe(on_state)
session.start()
# 앱을 끌 때
session.stop()
subscription.unsubscribe()
```

## 포트

포트는 SDK가 HTTP 전송, 로그인 정보 저장, 시계 같은 바깥 기능을 쓰는 연결 지점입니다. 앱이 원하는 구현으로 교체할 수 있습니다.

명세에서 쓰는 포트 이름은 표준 모듈 `random`, `logging`과 헷갈리지 않도록 다른 이름을 붙였습니다. Swift SDK, Kotlin SDK와 같은 이름입니다.

포트는 모두
`typing.Protocol`이라서 메서드 모양만 맞추면 됩니다.

| 포트(명세 이름) | 기본 구현 | 직접 구현하거나 설정할 항목 |
|---|---|---|
| `HttpTransport`(Transport) | `UrllibTransport`입니다. 표준 `urllib`을 쓰고, 시간 초과는 30초이며, 리다이렉트를 따라가지 않습니다. | 프록시나 인증서 고정이 필요하면 직접 구현해 주세요. 이때 리다이렉트를 따라가지 않게 하는 것은 앱이 맡습니다. |
| `CredentialStore` | **메모리**에만 둡니다. 앱을 끄면 로그인이 사라집니다. | `platform.default_credential_store`, `keyring_credential_store`, `dpapi_credential_store`, `secret_tool_credential_store`, `file_credential_store` |
| `FingerprintSource` | 없습니다. 실행할 때마다 새 기기로 보일 수 있으며, 이때 경고 로그를 남깁니다. | `platform.fingerprint_source(설치 ID 파일)`를 사용해 주세요. 운영체제에 따라 MachineGuid, IOPlatformUUID, machine-id를 쓰고, 읽지 못하면 설치 ID를 씁니다. |
| `WallClock`, `TaskScheduler`, `RandomSource`(Clock, Scheduler, Random) | 시스템 시계, `ThreadScheduler`(데몬 타이머 스레드), `secrets` | 시험할 때 교체합니다. SDK는 시간이나 다른 작업을 기다릴 때 `sleep`과 `wait`만 씁니다. |
| `LogSink`(Logger) | 아무것도 기록하지 않습니다(`SilentLog`). | 로그에는 토큰이나 기기 지문 원본이 넘어오지 않습니다. |

`default_credential_store`는 운영체제마다 저장하는 곳이 다릅니다.

- Windows: DPAPI로 보호한 파일에 저장합니다.
- Linux: Secret Service에 저장합니다. `secret-tool`이 없으면 권한 0600 파일에 저장하고 경고를 남깁니다.
- macOS: 권한 0600 파일에 저장하고 경고를 남깁니다.

macOS에서 기본으로 키체인을 쓰지 않는 이유는 `security` 명령이 비밀 값을 명령 인자로 받기 때문입니다. TS, Go, Kotlin SDK와 같은 이유입니다.

**macOS 키체인**을 쓰려면 `pip install "bydev[keyring]"`로 설치한 뒤 `platform.keyring_credential_store(client_id)`를 사용해 주세요. 이때 `keyring` 패키지가
키체인, Windows 자격 증명 관리자, Secret Service 가운데 알맞은 것을 선택합니다.

SDK는 비밀 값(refresh_token)을 명령줄 인자로 넘기지 않고,
`secret-tool`과 PowerShell에 표준 입력으로만 전달합니다.

**Linux 배포 패키지에는 `secret-tool`을 의존성으로 걸어 주세요.** 기본 저장소는 이 명령으로 Secret Service에 접근하는데, Debian과 Ubuntu 데스크톱의
기본 설치에는 이 명령이 없습니다.

Ubuntu 26.04.1에서 확인했으며, Secret Service 자체는 돌고 있었습니다. .deb 패키지는 `libsecret-tools`를 `Depends`나
`Recommends`에 넣고, RPM(Fedora 등)과 Arch 패키지는 `libsecret`을 넣어 주세요.

의존성을 지정할 수 없는 AppImage나 tar.gz 배포본에는 `secret-tool` 설치 방법을 안내해 주세요. 명령이 없으면 SDK는 권한 0600 파일에 저장하고 경고 로그를 남깁니다. `keyring_credential_store`는 D-Bus로 Secret Service에 바로 접근하므로 이
명령이 필요 없습니다.

이 점도 같은 Ubuntu에서 함께 확인했습니다.

## 판매자 서버

```python
from bydev import ServerVerifier, verify_webhook

# 웹훅: 받은 본문(bytes) 그대로 검증하세요. 파싱했다가 다시 만든 바이트로는 서명이 맞지 않습니다. 시크릿을 교체하는 중이면 둘 다 넘기세요
webhook = verify_webhook([secret], request.headers, request.body)

# 앱이 보낸 access_token과 licenseToken을 검증합니다. JWKS를 받아 캐시하므로 인스턴스 하나를 오래 쓰세요
verifier = ServerVerifier("https://api.developedby.dev", client_id)
claims = verifier.verify_access_token(token)
```

## 사용 조건

- **업데이트**: `check_for_update(target, current_version)`가 반환한 `update_status`가 `REQUIRED`이면, 업데이트하기 전까지 앱 실행을 막아 주세요.
  `install.mode`가 `HOSTED`일 때는 다운로드한 파일을 설치하기 전에 `verify_download(data, check.install.sha256)`로 확인해 주세요.
  업데이트 제공 기한이 있는 구매자는 결과에 `entitled`가 들어 있습니다. 그때는 최상위 대신 `entitled.release`를 따라 주세요.
  최상위 최신 버전은 그 구매자가 실행할 수 없는 버전일 수 있고, `entitled.release`가 비어 있으면 그 대상에 제공 범위 안의 버전이 없습니다.
- **오류**: 실패하면 `BydevError`가 발생합니다. 분기는 `code`로 하고, 비교할 값은 생성된 `Codes`에 있습니다. `message`는 화면에 보여 주는 용도로만
  사용해 주세요. `is_transient`가 참이면 다시 시도해 볼 만한 오류입니다.
- **모르는 값**: `EntitlementStatus` 같은 열거 값은 `str`입니다. 그래서 이 버전의 SDK가 모르는 새 값이 와도 그대로 담깁니다. `match`에는 `case _`를
  두어 주세요.

  모델은 frozen dataclass이고 속성 이름은 snake_case입니다. 모든 모델에는 `to_dict()`가 있어서 기록하거나 진단할 때 쓸 수 있으며, 이때 키는
  API와 같은 camelCase입니다.
- 패키지에 타입 힌트(`py.typed`)가 들어 있으며, mypy `--strict`로 검사합니다.
- 라이선스는 MIT 또는 Apache-2.0입니다.

## 출처 확인

이 꾸러미는 공개 저장소 `developedby-dev/sdk-python`의 GitHub Actions가 판 태그에서 짓고 올립니다. PyPI에 올린 파일에는 출처 증명(PEP 740)이 있습니다. PyPI 파일 화면의 「Provenance」에서 지은 저장소와 워크플로를 볼 수 있습니다.

## 개발

개발 명령은 [uv](https://docs.astral.sh/uv/)로 실행합니다.

| 명령 | 하는 일 |
|---|---|
| `uv run --frozen pytest -q` | 시험을 돌립니다. 실제 전송 시험은 적합성 시험용 가짜 서버를 HTTP 모드로 node에서 띄워 확인하며, 쓸 node는 `BYDEV_NODE`로 바꿀 수 있습니다. |
| `uv run --frozen ruff format .` | 서식을 맞춥니다. |
| `uv run --frozen ruff check .` · `uv run --frozen mypy` | 린트와 타입 검사(strict)를 합니다. |
| `uv run --frozen python harness/harness.py` | 적합성 하네스를 실행합니다. |
| `pnpm sdk:check python` | 린트, 서식, 타입 검사, 시험, 적합성 시나리오 48개를 모두 돌립니다. |

`src/bydev/_generated.py`는 생성된 파일이며, `pnpm --filter @bydev/sdk-codegen generate`로 다시 만듭니다. 이 파일은 ruff 검사에서 뺍니다.
