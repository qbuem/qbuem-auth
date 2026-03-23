# qbuem-auth

qbuem-stack 기반 C++23 인증 라이브러리.
HS256 JWT, OpenSSL HTTPS 클라이언트(비동기 래퍼), Google/GitHub/Discord/Microsoft/Facebook/Naver/Kakao OAuth2 를 제공합니다.

## 제공 컴포넌트

| 파일 | 설명 |
|------|------|
| `src/auth/jwt.hpp` | HS256 JWT 생성·검증 (OpenSSL 불필요, qbuem::crypto 전용) |
| `src/auth/https_client.hpp` | 경량 HTTPS 클라이언트 (OpenSSL BIO + eventfd 비동기 래퍼) |
| `src/auth/oauth.hpp` | Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao OAuth2 프로바이더 |

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
    TokenType   type;       // TokenType::Access | TokenType::Refresh
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
using namespace qbuem_routine;

// 액세스 토큰 발급 (TTL: 24h)
std::string access_token = jwt::encode(claims);

// 리프레시 토큰 발급 (TTL: 30d)
std::string refresh_token = jwt::encode_refresh(claims);

// 액세스 토큰 검증 + Claims 추출 (만료/서명/종류 불일치 시 nullopt)
std::optional<jwt::Claims> c = jwt::decode(token);

// 리프레시 토큰 검증
std::optional<jwt::Claims> c = jwt::decode(token, jwt::TokenType::Refresh);

// Authorization 헤더에서 Bearer 토큰 추출
std::optional<std::string_view> t = jwt::extract_bearer(auth_header);
```

### 토큰 갱신 흐름 예시

```cpp
// 리프레시 토큰으로 새 액세스 토큰 발급
auto rc = jwt::decode(refresh_token, jwt::TokenType::Refresh);
if (!rc) { /* 만료 또는 위조 → 재로그인 요청 */ }
std::string new_access = jwt::encode(*rc);
```

### 내부 구현

```
토큰 = base64url({"alg":"HS256","typ":"JWT"})
     . base64url(payload_json)
     . base64url(HMAC-SHA256(header.payload, secret))
```

- 서명 검증: `qbuem::crypto::constant_time_equal()` (타이밍 오라클 방지)
- Payload에 `"type":"access"|"refresh"` 필드 포함 → `decode()` 시 종류 검증
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
using namespace qbuem_routine;

// POST (기본 Content-Type: application/x-www-form-urlencoded)
auto resp = co_await https::post(url, body);
auto resp = co_await https::post(url, body, "application/json");

// POST + 추가 헤더
auto resp = co_await https::post(url, body,
    "application/x-www-form-urlencoded",
    "Authorization: Bearer token\r\n");

// GET
auto resp = co_await https::get(url);

// GET + 추가 헤더
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
   └─ state = state_store::issue()
   └─ Provider::authorize_url(state)  →  302 redirect to provider

2. GET /auth/{provider}/callback?code=...&state=...
   ├─ Provider::exchange(code, state)
   │    ├─ state_store::verify_and_consume(state)  →  CSRF 검증 (실패 시 nullopt)
   │    ├─ co_await https::post(token_endpoint, body)  →  access_token
   │    └─ co_await https::get(userinfo_endpoint, "Authorization: Bearer ...")  →  UserInfo
   └─  jwt::encode(Claims{...})  →  액세스 토큰
       jwt::encode_refresh(Claims{...})  →  리프레시 토큰
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
| GitHub | github.com/login/oauth/authorize | github.com/login/oauth/access_token | api.github.com/user |
| Discord | discord.com/api/oauth2/authorize | discord.com/api/oauth2/token | discord.com/api/users/@me |
| Microsoft | login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize | login.microsoftonline.com/{tenant}/oauth2/v2.0/token | graph.microsoft.com/v1.0/me |
| Facebook | facebook.com/v20.0/dialog/oauth | graph.facebook.com/v20.0/oauth/access_token | graph.facebook.com/v20.0/me |

### CSRF State 관리

```cpp
// 발급 (TTL 10분, in-memory)
std::string state = state_store::issue();

// 검증 + 소비 (1회용) — exchange() 내부에서 자동 호출됨
bool ok = state_store::verify_and_consume(state);
```

- `qbuem::crypto::csrf_token(128)` — 128-bit CSPRNG URL-safe base64url 토큰 생성
- `std::mutex` 로 스레드 안전 보장
- `issue()` 호출 시 만료된 엔트리 자동 정리
- `verify_and_consume()` — 검증과 동시에 삭제 (재사용 불가)

### 프로바이더 API

모든 `exchange()` 함수는 `state` 파라미터를 받아 **내부에서 CSRF 검증**을 수행합니다.

```cpp
#include "auth/oauth.hpp"
using namespace qbuem_routine;

// 인가 URL 생성
auto state = oauth::state_store::issue();
std::string url = oauth::GoogleProvider::authorize_url(state);
std::string url = oauth::NaverProvider::authorize_url(state);
std::string url = oauth::KakaoProvider::authorize_url(state);
std::string url = oauth::GitHubProvider::authorize_url(state);
std::string url = oauth::DiscordProvider::authorize_url(state);
std::string url = oauth::MicrosoftProvider::authorize_url(state);
std::string url = oauth::FacebookProvider::authorize_url(state);

// 코드 교환 → UserInfo (state CSRF 검증 포함)
auto info = co_await oauth::GoogleProvider::exchange(code, state);    // optional<UserInfo>
auto info = co_await oauth::NaverProvider::exchange(code, state);
auto info = co_await oauth::KakaoProvider::exchange(code, state);
auto info = co_await oauth::GitHubProvider::exchange(code, state);
auto info = co_await oauth::DiscordProvider::exchange(code, state);
auto info = co_await oauth::MicrosoftProvider::exchange(code, state);
auto info = co_await oauth::FacebookProvider::exchange(code, state);
```

### 각 프로바이더 특이사항

| 프로바이더 | 특이사항 |
|-----------|---------|
| **Google** | OIDC(openid+email+profile), userinfo Authorization 헤더 사용 |
| **Naver** | state를 토큰 요청에도 포함 (Naver 스펙) |
| **Kakao** | `id` 필드가 정수형(`"id":1234`), `kakao_account.profile` 중첩 구조 |
| **GitHub** | `User-Agent` 헤더 필수, `Accept: application/json` 토큰 요청 필수, 이메일 비공개 시 `/user/emails`에서 primary 이메일 자동 조회 |
| **Discord** | 아바타 URL을 `id`+`avatar_hash`로 조합, `global_name` 없으면 `username` 사용 |
| **Microsoft** | 테넌트 `MICROSOFT_TENANT_ID` (기본: `common`), 이메일은 `mail` → `userPrincipalName` 순 |
| **Facebook** | 토큰 교환이 GET 방식(비표준), picture는 `picture.data.url` 중첩 구조 |

모든 프로바이더의 사용자 정보 API 액세스 토큰은 **URL 파라미터가 아닌 `Authorization: Bearer` 헤더**로 전달됩니다. (Facebook 토큰 교환 단계는 예외)

### 환경변수

```
GOOGLE_CLIENT_ID,    GOOGLE_CLIENT_SECRET
NAVER_CLIENT_ID,     NAVER_CLIENT_SECRET
KAKAO_CLIENT_ID,     KAKAO_CLIENT_SECRET
GITHUB_CLIENT_ID,    GITHUB_CLIENT_SECRET
DISCORD_CLIENT_ID,   DISCORD_CLIENT_SECRET
MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET
MICROSOFT_TENANT_ID  (기본값: common — 멀티테넌트)
FACEBOOK_CLIENT_ID,  FACEBOOK_CLIENT_SECRET
OAUTH_REDIRECT_BASE  (예: https://your-domain.com, 기본값: http://localhost:8080)
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
