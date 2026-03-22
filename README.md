# qbuem-auth

qbuem-stack 기반 C++23 인증 라이브러리.
HS256 JWT, OpenSSL HTTPS 클라이언트(비동기 래퍼), Google/Naver/Kakao OAuth2 를 제공합니다.

## 제공 컴포넌트

| 파일 | 설명 |
|------|------|
| `src/auth/jwt.hpp` | HS256 JWT 생성·검증 (OpenSSL 불필요, qbuem::crypto 전용) |
| `src/auth/https_client.hpp` | 경량 HTTPS 클라이언트 (OpenSSL BIO + eventfd 비동기 래퍼) |
| `src/auth/oauth.hpp` | Google / Naver / Kakao OAuth2 프로바이더 |

## 빌드 의존성

| 의존성 | 관리 방법 |
|--------|---------|
| qbuem-stack | `FetchContent` (GIT) |
| OpenSSL | `find_package(OpenSSL REQUIRED)` — HTTPS TLS 전용 |

> JWT는 qbuem::crypto (HMAC-SHA256 + Base64url) 만으로 구현되어 OpenSSL이 필요 없습니다.
> OpenSSL은 OAuth 아웃바운드 HTTPS 요청(`https_client.hpp`)에만 사용됩니다.

## 사용법 (FetchContent)

```cmake
FetchContent_Declare(
    qbuem_auth
    GIT_REPOSITORY https://github.com/qbuem/qbuem-auth.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(qbuem_auth)

target_link_libraries(your_target PRIVATE qbuem-auth::auth)
```

---

## JWT (`src/auth/jwt.hpp`)

RFC 7519 HS256 JWT 생성·검증. qbuem::crypto 모듈만 사용합니다.

### Claims 구조

```cpp
struct Claims {
    int64_t     sub;        // 사용자 DB ID
    std::string provider;   // "google" | "naver" | "kakao"
    std::string email;
    std::string name;
    int64_t     iat;        // 발급 시각 (Unix 초)
    int64_t     exp;        // 만료 시각 (Unix 초)
};
```

### 만료 기간

| 상수 | 값 |
|------|-----|
| `kAccessTokenTTL`  | 24시간 |
| `kRefreshTokenTTL` | 30일 |

### 비밀 키 관리

환경변수 `JWT_SECRET` (≤32 bytes)이 있으면 사용, 없으면 프로세스 시작 시 CSPRNG로 32-byte 키 자동 생성.

### API

```cpp
#include "auth/jwt.hpp"

// 토큰 발급
std::string token = jwt::encode(claims);

// 토큰 검증 + Claims 추출 (만료/서명 오류 시 nullopt)
std::optional<jwt::Claims> c = jwt::decode(token);

// Authorization 헤더에서 Bearer 토큰 추출
std::optional<std::string_view> t = jwt::extract_bearer(auth_header);
```

### 내부 구현

```
토큰 = base64url({"alg":"HS256","typ":"JWT"})
     . base64url(payload_json)
     . base64url(HMAC-SHA256(header.payload, secret))
```

- 서명 검증: `qbuem::crypto::constant_time_equal()` (타이밍 오라클 방지)
- Payload JSON 직렬화: `std::format` (외부 JSON 라이브러리 불필요)
- Base64url: 패딩 없음 (`false`)

---

## HTTPS 클라이언트 (`src/auth/https_client.hpp`)

OAuth 토큰 교환 등 빈도가 낮은 아웃바운드 HTTPS 요청 전용 경량 클라이언트.

### 비동기 구현 패턴

```
co_await https::post(url, body)
  │
  ├─ eventfd 생성
  ├─ std::thread::detach()  → OpenSSL BIO 블로킹 I/O (Reactor 스레드 비블로킹)
  │     └─ 완료 시 eventfd write(1)
  └─ EventFdAwaiter
        ├─ Reactor::register_event(efd, Read, ...)
        └─ 완료 이벤트 → Reactor::post(coroutine.resume())
```

블로킹 OpenSSL 호출을 별도 스레드에서 실행하고, 완료를 eventfd로 Reactor에 알려 코루틴을 재개합니다. Reactor 스레드는 블로킹되지 않습니다.

### TLS 설정

- `SSL_CTX_set_default_verify_paths()` — 시스템 CA 번들 사용
- `SSL_VERIFY_PEER` — 인증서 검증 활성화
- SNI 지원 (`SSL_set_tlsext_host_name`)
- HTTP/1.1, `Connection: close`
- `ssl_init()` — `std::call_once` 로 스레드 안전 초기화

### Response 구조체

```cpp
struct Response {
    int         status = 0;
    std::string body;
    bool ok() const noexcept { return status >= 200 && status < 300; }
};
```

### API

```cpp
#include "auth/https_client.hpp"

// POST (기본 Content-Type: application/x-www-form-urlencoded)
auto resp = co_await https::post(url, body);
auto resp = co_await https::post(url, body, "application/json");

// POST + 추가 헤더
auto resp = co_await https::post(url, body,
    "application/x-www-form-urlencoded",
    "Authorization: Bearer token\r\n");

// GET
auto resp = co_await https::get(url);

// GET + 추가 헤더 (예: Naver API)
auto resp = co_await https::get(url, "Authorization: Bearer token\r\n");

if (resp.ok()) { /* resp.body ... */ }
```

### URL 파싱

`https://host[:port]/path?query` 형식 자동 파싱. 포트 기본값 443 (http: 80).

### 추가 헤더 형식

`extra_headers` 파라미터는 각 헤더를 `\r\n` 으로 끝내는 문자열을 이어 붙인 형태입니다.

```cpp
"Authorization: Bearer abc123\r\n"
"X-Custom-Header: value\r\n"
```

---

## OAuth2 (`src/auth/oauth.hpp`)

Google, Naver(한국), Kakao(한국) OAuth2 프로바이더 통합.

### 인증 흐름

```
1. GET /auth/{provider}/login
   └─ Provider::authorize_url(state)  →  302 redirect to provider

2. GET /auth/{provider}/callback?code=...&state=...
   ├─ state_store::verify_and_consume(state)  →  CSRF 검증
   ├─ Provider::exchange(code)
   │    ├─ co_await https::post(token_endpoint, body)  →  access_token
   │    └─ co_await https::get(userinfo_endpoint)       →  UserInfo
   └─  jwt::encode(Claims{...})  →  JWT 반환
```

### UserInfo 구조체

```cpp
struct UserInfo {
    std::string provider;     // "google" | "naver" | "kakao"
    std::string provider_id;  // 프로바이더 내 고유 ID
    std::string email;
    std::string name;
    std::string avatar_url;
};
```

### 프로바이더별 엔드포인트

| 프로바이더 | 인가 URL | 토큰 엔드포인트 | 사용자 정보 |
|-----------|---------|--------------|-----------|
| Google | accounts.google.com/o/oauth2/v2/auth | oauth2.googleapis.com/token | googleapis.com/oauth2/v3/userinfo |
| Naver | nid.naver.com/oauth2.0/authorize | nid.naver.com/oauth2.0/token | openapi.naver.com/v1/nid/me |
| Kakao | kauth.kakao.com/oauth/authorize | kauth.kakao.com/oauth/token | kapi.kakao.com/v2/user/me |

### CSRF State 관리

```cpp
// 발급 (TTL 10분, in-memory)
std::string state = state_store::issue();

// 검증 + 소비 (1회용)
bool ok = state_store::verify_and_consume(state);
```

- `qbuem::crypto::csrf_token(128)` — 128-bit CSPRNG URL-safe base64url 토큰 생성
- `std::mutex` 로 스레드 안전 보장
- `issue()` 호출 시 만료된 엔트리 자동 정리

### 프로바이더 API

```cpp
#include "auth/oauth.hpp"

// 인가 URL 생성
std::string url = GoogleProvider::authorize_url(state);
std::string url = NaverProvider::authorize_url(state);
std::string url = KakaoProvider::authorize_url(state);

// 코드 교환 → UserInfo
auto info = co_await GoogleProvider::exchange(code);          // optional<UserInfo>
auto info = co_await NaverProvider::exchange(code, state);    // state 파라미터 필요
auto info = co_await KakaoProvider::exchange(code);
```

### Naver 특이사항

Naver 사용자 정보 API는 액세스 토큰을 **URL 파라미터가 아닌 `Authorization: Bearer` 헤더**로 전달합니다.
라이브러리 내부에서 `https::get(url, "Authorization: Bearer <token>\r\n")` 형태로 처리되므로 별도 설정 불필요합니다.

### Kakao 특이사항

Kakao 응답의 `id` 필드는 JSON 정수(`"id":1234`)로 반환됩니다.
`json_get_field()` 헬퍼가 문자열·정수 형식 모두 지원하므로 자동 처리됩니다.

### 환경변수

```
GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
NAVER_CLIENT_ID,  NAVER_CLIENT_SECRET
KAKAO_CLIENT_ID,  KAKAO_CLIENT_SECRET
OAUTH_REDIRECT_BASE   (예: https://your-domain.com, 기본값: http://localhost:8080)
```

---

## 빌드

```bash
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_COMPILER=g++-13 \
      -DCMAKE_CXX_STANDARD=23 \
      -B build
cmake --build build
```

**요구사항**: GCC ≥ 13 / Clang ≥ 17, CMake ≥ 3.20, libssl-dev (OpenSSL)

---

## LLM 컨텍스트 파일

| 파일 | 설명 |
|------|------|
| `llms.txt` | 핵심 API 요약 (간략) |
| `llms_full.txt` | 전체 소스 코드 (상세) |
