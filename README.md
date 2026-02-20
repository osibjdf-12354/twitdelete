# twitdelete

트윗 자동 삭제 스크립트 모음입니다.

- `twitdelete_official.py`: 공식 X API v2 기반 (권장)
- `twitdelete.py`: X 웹 내부 GraphQL 기반 (레거시/우회용)

## 설치

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## GUI 실행

체크박스/입력창으로 옵션을 선택하고 버튼으로 실행하려면:

```bash
python twitdelete_gui.py
```

- GUI는 `legacy` 전용으로 동작하며 내부적으로 `twitdelete.py`를 실행합니다.
- 상단 실행 설정 블록은 숨김 처리되어 보이지 않습니다.
- 브라우저 기본값은 `edge`입니다.
- 기본 모드는 실제 삭제(`dry run` 해제)입니다.
- `auto-auth`는 항상 적용되며 GUI에서 입력받지 않습니다.
- 하단 `실행 로그` 창에 실행 출력이 계속 표시됩니다.
- `실행` / `중지` 버튼으로 제어
- GUI에서 `dry run` 체크 시 후보만 출력하고 삭제는 하지 않습니다.
- 실행 시 모드에 따라 확인 팝업이 표시됩니다(실삭제/DRY-RUN).

### GUI EXE 빌드

Windows에서 exe 생성:

```bat
build_gui_exe.bat
```

생성 파일:

```text
dist\twitdelete-gui.exe
```

참고:
- exe 내부 GUI는 백엔드 스크립트 실행 시 로컬 Python(`py` 또는 `python`)을 사용합니다.

## 1) 공식 API 방식 (권장)

공식 엔드포인트:
- `GET /2/users/me`
- `GET /2/users/{id}/tweets`
- `DELETE /2/tweets/{id}`

참고 문서:
- https://docs.x.com/x-api/users/get-my-user
- https://docs.x.com/x-api/users/get-posts
- https://docs.x.com/x-api/posts/delete-post

### 인증

`auth.example.json` 참고해서 `auth.json` 생성:

```json
{
  "access_token": "x_oauth2_user_access_token_here"
}
```

또는 환경변수 `X_ACCESS_TOKEN` 사용 가능.

토큰을 자동으로 파일에 넣고 싶으면(권장):

```bash
py get_x_user_token.py --client-id <YOUR_CLIENT_ID>
```

- 브라우저 승인 후 `auth.json`에 `access_token`(및 가능하면 `refresh_token`)이 저장됩니다.
- 사전 준비: X 개발자 앱에서 OAuth 2.0 활성화 + Callback URL 설정
  - 기본 콜백 URL: `http://127.0.0.1:8765/callback`

### 실행 예시

후보만 확인:

```bash
python twitdelete_official.py --dry-run --max 50
```

실제 삭제:

```bash
python twitdelete_official.py --max 50
```

전부 삭제(자동 반복):

```bash
python twitdelete_official.py --delete-all
```

429 자동 대기 포함:

```bash
python twitdelete_official.py --delete-all --rate-limit-mode wait --rate-limit-retries 50
```

리플 포함:

```bash
python twitdelete_official.py --include-replies --max 100
```

필터:

```bash
python twitdelete_official.py --before 2024-01-01 --contains "테스트"
```

### 주요 옵션

- `--timeline-pages`: 패스당 페이지 수
- `--timeline-page-size`: 페이지당 조회 수(5~100)
- `--include-replies`: 리플 포함 (기본은 제외)
- `--exclude-retweets`: 리트윗 제외
- `--max`: 최대 처리 개수
- `--delete-all`: 조회/삭제 패스 반복
- `--pass-delay`, `--pass-limit`: 반복 제어
- `--rate-limit-mode`, `--rate-limit-retries`, `--rate-limit-wait`, `--rate-limit-max-wait`: 429 처리
- `--before`, `--after`, `--contains`, `--author`: 필터
- `--dry-run`: 실제 삭제 없이 후보만 출력

## 2) 웹 내부 API 방식 (레거시)

공식 API 토큰이 없을 때 사용하던 방식입니다.

- 스크립트: `twitdelete.py`
- 브라우저 쿠키/CDP 기반 인증
- X 웹 변경에 더 취약함

레이트리밋(429) 줄이려면 패스당 처리량을 낮춰 실행:

```bash
python twitdelete.py --auto-auth --browser edge --cdp-url http://127.0.0.1:9222 --delete-all --batch-limit 20 --delay 1.5
```

`--include-replies`를 안정적으로 쓰려면 `x-client-transaction-id` 헤더가 필요한 경우가 있습니다.
현재 스크립트는 `--cdp-url`이 있으면 브라우저 네트워크에서 이 값을 자동 캡처해 사용합니다.
실행 중 `UserTweetsAndReplies`가 404를 반환하면 transaction id를 CDP에서 1회 재캡처 후 재시도하고,
그래도 404면 `UserTweets`로 폴백합니다.

필요할 때만 사용하고, 가능하면 `twitdelete_official.py`를 권장합니다.
