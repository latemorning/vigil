# vigil

로그 파일에서 개인정보(PII)를 검출하고, 어느 소스 모듈이 개인정보를 흘리고 있는지 역추적하는 CLI 도구입니다.

## 설치

```bash
pip install -e ".[dev]"
```

또는 venv를 직접 사용하는 경우:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 빠른 시작

```bash
# 단일 파일 스캔
vigil scan app.log

# 디렉터리 재귀 스캔
vigil scan /var/log/myapp/

# 결과를 파일로 저장 (기본값: vigil-report.json)
vigil scan /var/log/myapp/ --output report.json
```

## 검출 항목

| 디텍터 | 이름 | 설명 |
|---|---|---|
| 주민등록번호 | `rrn` | 6자리-7자리, 체크섬 검증 |
| 휴대폰 번호 | `phone_mobile` | 010/011/016/017/018/019 |
| 일반전화 번호 | `phone_landline` | 02/031~070/080 |
| 사업자등록번호 | `business_number` | 000-00-00000, 체크섬 검증 |
| 연계정보(CI) | `ci` | 88자 Base64, 라벨 유무로 신뢰도 구분 |
| 한국식 이름 | `name_korean` | 컨텍스트 키워드(high) + 성씨 휴리스틱(low) |
| 이메일 | `email` | RFC 이메일 형식 |
| 신용카드 번호 | `credit_card` | 13~19자리, Luhn 체크섬 검증 |
| IPv4 주소 | `ipv4` | 0.0.0.0~255.255.255.255 |

## 옵션

```
vigil scan <경로> [옵션]

  -o, --output FILE         JSON 리포트 저장 경로 (기본값: vigil-report.json)
  --ext EXTS                스캔할 확장자, 쉼표 구분 (기본값: .log .txt 및 확장자 없는 파일)
  --detector NAMES          활성화할 디텍터 이름, 쉼표 구분 (기본값: 전체)
  --min-confidence {high,low}  리포트할 최소 신뢰도 (기본값: low)
  -q, --quiet               터미널 요약 출력 생략
  --name-stopwords FILE     한국 이름 검출에서 제외할 단어 목록 파일 (UTF-8, # 주석 허용)
```

## 사용 예시

### 특정 디텍터만 사용

```bash
vigil scan app.log --detector email,rrn,phone_mobile
```

### 신뢰도 high 결과만 리포트

```bash
vigil scan app.log --min-confidence high
```

### 회사 고유 명칭을 이름 검출에서 제외

프로덕트명, 지명, 카드사명 등이 한국 이름으로 오탐되는 경우 stopwords 파일로 제외할 수 있습니다.

```text
# company_terms.txt
# 프로덕트명
네이버페이
카카오페이

# 지명
강남점
```

```bash
vigil scan app.log --name-stopwords company_terms.txt
```

### CI/CD 통합 (종료 코드)

| 종료 코드 | 의미 |
|---|---|
| `0` | PII 미검출 |
| `1` | PII 검출됨 |
| `2` | 실행 오류 (경로 없음, 잘못된 옵션 등) |

```bash
vigil scan app.log --quiet --output /tmp/report.json
if [ $? -eq 1 ]; then
  echo "PII 검출됨 — 배포 중단"
  exit 1
fi
```

## 터미널 출력 예시

```
Scanned 1 files (199 B)
Found 4 matches (high: 4, low: 0):
┏━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Detector    ┃ Matches ┃ Confidence ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━┩
│ rrn         │ 1       │ high       │
│ email       │ 1       │ high       │
│ credit_card │ 1       │ high       │
│ name_korean │ 1       │ high       │
└─────────────┴─────────┴────────────┘

Top 5 source modules:
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Source module           ┃ Matches ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ vigil.auth.login        │ 2       │
│ vigil.payment.processor │ 1       │
│ app.user                │ 1       │
└─────────────────────────┴─────────┘
```

## JSON 리포트 형식

```json
{
  "scanned_at": "2026-04-23T10:17:52+09:00",
  "root": "/var/log/myapp/app.log",
  "files_scanned": 1,
  "bytes_scanned": 199,
  "total_matches": 4,
  "by_detector": {
    "rrn": 1,
    "email": 1
  },
  "matches": [
    {
      "file": "/var/log/myapp/app.log",
      "line": 1,
      "column": 53,
      "detector": "email",
      "value": "hong@example.com",
      "confidence": "high",
      "source_module": "com.example.auth.LoginService"
    }
  ]
}
```

### `source_module` 필드

로그 라인의 prefix에서 로거 이름을 추출해 각 매치에 붙입니다. Python `logging` 모듈과 WildFly/JBoss 등 주요 포맷을 지원합니다.

| 지원 포맷 | 예시 |
|---|---|
| Python asctime + dash | `2026-04-21 12:00:00,123 INFO my.module - message` |
| Python asctime + colon | `2026-04-21 12:00:00 INFO my.module: message` |
| Python basicConfig | `INFO:my.module:message` |
| 대괄호 스타일 | `[2026-04-21 12:00:00] [INFO] [my.module] message` |
| WildFly/JBoss | `... 2026-04-21 12:00:00.000 [INFO ] [thread] com.example.MyService - message` |

로거 이름을 파싱할 수 없는 라인의 매치는 `source_module: null`로 표시됩니다.

## 개발

```bash
# 테스트 실행
python -m pytest -v

# 특정 테스트만
python -m pytest tests/test_detectors_korean.py -v
```

## 한국 이름 검출 신뢰도

| 신뢰도 | 조건 | 예시 |
|---|---|---|
| `high` | `이름=`, `name=`, `성명=` 등 컨텍스트 키워드 뒤에 한글 2~4자 | `이름=홍길동` |
| `low` | 한국 성씨로 시작하는 한글 2~4자 (휴리스틱) | `담당자 박수진 연락처` |

오탐이 많을 경우 `--min-confidence high` 또는 `--name-stopwords` 옵션을 사용하세요.
