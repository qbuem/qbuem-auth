# qbuem-auth — 개발 가이드 (CLAUDE.md)

## 프로젝트 개요

C++23 헤더-온리 인증 라이브러리.
HS256 JWT + 경량 비동기 HTTPS 클라이언트 + 7개 OAuth2 프로바이더 (Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao).

```
src/auth/
  jwt.hpp          — HS256 JWT 생성·검증 (qbuem::crypto only)
  https_client.hpp — OpenSSL BIO + eventfd Reactor 비동기 래퍼
  oauth.hpp        — OAuth2 프로바이더 (UserInfo 공통 구조)
```

---

## 설계 원칙 및 고성능 구현 로드맵

### 목표: Zero-Copy · Zero-Latency

현재 구현은 정확성과 단순성을 우선으로 작성되었다.
**고성능 버전에서는 아래의 복사 지점과 지연 요소를 제거해야 한다.**

---

## Zero-Copy: 현황 점검

### ✅ 이미 zero-copy인 경로

| 위치 | 내용 |
|------|------|
| `detail::json_get_obj()` | `std::string_view` 반환 — 파싱 결과 무복사 |
| `jwt::extract_bearer()` | `std::optional<std::string_view>` — 헤더 슬라이스 무복사 |
| `do_https_blocking()` 인자 | 모두 `std::string_view` — 호출 인터페이스 무복사 |
| `jwt::encoded_header()` | `static const std::string` — 1회 생성 후 재사용 |
| `state_store::verify_and_consume()` | `std::string_view` 인자 |

### ❌ 고성능 구현 시 제거해야 할 복사 지점

#### 1. `https::post()` / `https::get()` — 파라미터 방어 복사 (`https_client.hpp:223-225`)

```cpp
// 현재: detached thread에 넘기기 위해 std::string으로 복사
std::string host_copy{host}, path_copy{path};
std::string body_copy{body}, ct_copy{content_type};
std::string hdrs_copy{extra_headers};
```

**원인**: detached thread가 호출자보다 오래 살 수 있어 string_view가 댕글링될 위험.
**고성능 대안**:
- 스레드 풀(thread pool) + `std::packaged_task` → 코루틴이 await 중 string_view가 유효함을 보장
- 또는 파라미터를 `std::string` 값으로 받아 move 전달 (`std::string&&`)

#### 2. `do_https_blocking()` — 이중 버퍼링 (`https_client.hpp:125-148`)

```cpp
// 현재: 스택 버퍼 → raw(std::string) → resp_body(std::string) 두 번 복사
char buf[4096];
std::string raw;
while ((n = BIO_read(bio, buf, sizeof(buf))) > 0)
    raw.append(buf, n);               // 1차 복사: buf → raw

resp_body = raw.substr(sep + 4);      // 2차 복사: raw 일부 → resp_body
```

**고성능 대안**:
- `BIO_read`를 직접 최종 버퍼에 수신 (헤더 크기를 먼저 파악 후 body 오프셋 계산)
- 또는 `raw`에서 body 부분을 `substr` 대신 `move` + erase-front로 처리
  ```cpp
  raw.erase(0, sep + 4);    // body 앞 헤더 제거 → in-place, 재할당 없음
  return {status, std::move(raw)};
  ```
  > **즉시 적용 가능**: `raw.substr(sep+4)`를 `raw.erase(0, sep+4); return {status, std::move(raw)};`로 교체하면 2차 복사 제거.

#### 3. `detail::json_get_field()` — 필드마다 heap 할당 (`oauth.hpp:75-123`)

```cpp
// 현재: 추출 결과를 항상 std::string으로 반환 (heap 할당)
std::string out;        // 문자열 필드
return std::string{val}; // 스칼라 필드
```

**원인**: 이스케이프 시퀀스 처리가 필요하므로 단순 view 반환 불가.
**고성능 대안**:
- **Fast path** (이스케이프 없음): `std::string_view` 반환 → 완전 zero-copy
- **Slow path** (이스케이프 포함): 기존 `std::string` 반환
- 시그니처 예시:
  ```cpp
  // variant 또는 별도 함수로 분리
  std::string_view json_get_field_view(std::string_view json, std::string_view key);
  std::string      json_get_field(std::string_view json, std::string_view key);
  ```
- **단, UserInfo 필드를 string_view로 바꾸면 response body의 수명 관리가 필요해짐.**

#### 4. `UserInfo` — 응답 바디에서 추출한 문자열 재복사 (`oauth.hpp:43-49`)

```cpp
// 현재: 모든 필드가 std::string (response body에서 복사)
struct UserInfo {
    std::string provider;
    std::string provider_id;
    std::string email;
    std::string name;
    std::string avatar_url;
};
```

**고성능 대안** (수명 관리 부담 있음):
```cpp
// response body를 shared_ptr로 관리, UserInfo는 view만 보유
struct UserInfo {
    std::shared_ptr<std::string> _body;   // 소유권
    std::string_view provider;
    std::string_view provider_id;
    std::string_view email;
    std::string_view name;
    std::string_view avatar_url;
};
```
> provider는 kName을 가리키는 view이므로 수명 무관.

#### 5. `jwt::extract_str()` — payload 파싱마다 heap 할당 (`jwt.hpp:139-170`)

```cpp
// 현재: decode()에서 extract_str() 5회 호출 → 최소 5번 heap 할당
claims.provider = detail::extract_str(payload, "provider");
claims.email    = detail::extract_str(payload, "email");
claims.name     = detail::extract_str(payload, "name");
```

**고성능 대안**:
- JWT payload의 문자열 필드는 우리가 직접 `json_str()`로 이스케이프하여 생성.
  `provider`, `email`, `name`에 제어문자(`"`, `\`)가 없다고 검증된 경우 `string_view` 반환 가능.
- `Claims` 구조체도 `string_view` 기반으로 전환 가능 (단, payload 수명 연장 필요).

#### 6. `json_get_field`/`json_get_obj` 내부 패턴 문자열 — 호출마다 `std::format` 할당

```cpp
auto k_str = std::format(R"("{}":")", key);   // 매 호출마다 heap 할당
auto k     = std::format(R"("{}":{{)", key);  // 매 호출마다 heap 할당
```

**고성능 대안**: 컴파일 타임 키가 알려진 경우 문자열 리터럴 직접 사용.
```cpp
// 예: json_get_field(j, "access_token") 대신
constexpr auto kAccessTokenKey = R"("access_token":")";
auto pos = j.find(kAccessTokenKey);
```

---

## Zero-Latency: 현황 점검

### ❌ 고성능 구현 시 제거해야 할 지연 요소

#### 1. 요청마다 새 TLS 세션 생성 — 가장 큰 지연 요인

```
현재 흐름 (exchange() 1회 = TLS 핸드셰이크 2~3회):
  SSL_CTX_new → BIO_new_ssl_connect → BIO_do_connect → BIO_do_handshake
  ↑ 토큰 요청 시 1회 + 사용자 정보 요청 시 1회 + (Microsoft: photo 1회)
```

**원인**: `https_client.hpp`의 `do_https_blocking()`이 매 호출마다 독립적인 TLS 연결을 생성하고 `Connection: close`로 닫음.

**고성능 대안**: 호스트별 TLS 연결 풀 (connection pool).
- `std::unordered_map<std::string, BIO*>` 또는 `ssl_session` 재사용
- TLS Session Resumption (SSL_SESSION 재사용)

#### 2. 요청마다 새 `std::thread` 생성 (`https_client.hpp:229-235`)

```cpp
std::thread([=]() mutable { ... }).detach();  // 매 요청마다 OS 스레드 생성
```

**고성능 대안**: 스레드 풀 (예: `qbuem::Executor` 또는 `std::async` + 고정 풀).

#### 3. `SSL_CTX_new` 매 요청 생성

```cpp
SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());  // 매 요청마다
```

**고성능 대안**: `SSL_CTX` 전역 싱글톤 (인증서, 검증 설정 포함).
```cpp
// ssl_init()에서 ctx도 함께 초기화
inline SSL_CTX* ssl_ctx() {
    static SSL_CTX* ctx = []() { ... }();
    return ctx;
}
```

#### 4. `state_store` 글로벌 뮤텍스 — 고동시성 병목

```cpp
inline std::mutex g_mutex;  // 모든 프로바이더가 공유
```

**고성능 대안**: sharded lock (버킷별 뮤텍스) 또는 lock-free 구조.

#### 5. `authorize_url()` — 매 호출마다 URL 재조립

`std::format` 기반 URL 조립은 환경변수 값이 변하지 않는 한 캐싱 가능.
`client_id`, `redirect_uri`는 정적이므로 `state` 부분만 교체하는 방식으로 최적화 가능.

---

## 즉시 적용 가능한 개선 (하위 호환성 유지)

우선순위 순:

1. **`raw.substr(sep+4)` → in-place erase + move** (`https_client.hpp:148`)
   - 2차 복사 1건 제거, 인터페이스 변경 없음

2. **`SSL_CTX` 공유 싱글톤화** (`https_client.hpp:68`)
   - `SSL_CTX_new` 비용 제거, 스레드 안전

3. **`json_get_field` fast-path: 이스케이프 없는 경우 `string_view` 오버로드 추가**
   - 기존 함수 유지하면서 고속 경로 추가

---

## 코드 규칙

- **새 프로바이더 추가 시**: `kName` 상수 정의 → `exchange()`에서 `.provider = std::string{kName}` 사용 (하드코딩 금지)
- **`authorize_url()`**: `state` 파라미터는 반드시 `qbuem::url_encode(state)` 적용
- **`json_get_obj()` 결과**: 빈 뷰 체크 후 사용 (`empty()` guard)
- **중첩 JSON**: `json_get_obj()` 체이닝 사용 (Naver/Kakao/Facebook 패턴 참조)
- **헤더 문자열**: `"HeaderName: value\r\n"` 형식, 마지막 `\r\n` 필수
- **환경변수**: `detail::env_or("KEY", "default")` 사용

## 알려진 한계 (현재 구현)

- Chunked transfer encoding 미지원 — OAuth API 실응답은 compact, 실영향 낮음
- `json_get_obj()` 객체 경계 미한정 — 동명 필드 오탐 가능성 (실응답 구조상 해당 없음)
- `JWT_SECRET` 32바이트 초과 시 절단, 미만 시 zero-padding
- Microsoft `avatar_url`은 Bearer 토큰 인증 필요 엔드포인트 (`/me/photo/$value`)

## 의존성

- **qbuem-stack**: `qbuem::crypto`, `qbuem::url_encode/decode`, `qbuem::Reactor`, `qbuem::Task<T>`
- **OpenSSL**: HTTPS 아웃바운드 전용 (JWT에는 미사용)
