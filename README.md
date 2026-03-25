# qbuem-auth

C++23 authentication library built on qbuem-stack.
HS256 JWT, OpenSSL HTTPS client (async wrapper), and OAuth2 for Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao.

## Components

| File | Description |
|------|-------------|
| `src/auth/jwt.hpp` | HS256 JWT creation and verification (qbuem::crypto only, no OpenSSL) |
| `src/auth/https_client.hpp` | Lightweight HTTPS client (OpenSSL BIO + eventfd async wrapper) |
| `src/auth/oauth.hpp` | Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao OAuth2 providers |

## Build Dependencies

| Dependency | Management | Purpose |
|------------|-----------|---------|
| qbuem-stack | `FetchContent` (GIT) | Interfaces, Reactor, Task, crypto |
| OpenSSL | `find_package(OpenSSL REQUIRED)` | HTTPS TLS only |

> JWT is implemented using `qbuem::crypto` (HMAC-SHA256 + Base64url) only — no OpenSSL required.
> OpenSSL is used exclusively for outbound OAuth HTTPS requests (`https_client.hpp`).

## Usage (FetchContent)

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

RFC 7519 HS256 JWT creation and verification. Uses only the `qbuem::crypto` module.

### Claims Structure

```cpp
struct Claims {
    int64_t     sub;        // User DB ID
    std::string provider;   // "google" | "naver" | "kakao"
    std::string email;
    std::string name;
    int64_t     iat;        // Issued-at (Unix seconds)
    int64_t     exp;        // Expiry (Unix seconds)
    TokenType   type;       // TokenType::Access | TokenType::Refresh
};
```

### TTL Constants

| Constant | Value |
|----------|-------|
| `kAccessTokenTTL`  | 24 hours |
| `kRefreshTokenTTL` | 30 days |

### Secret Key Management

If the environment variable `JWT_SECRET` (≤ 32 bytes) is set it is used as the signing key; otherwise a 32-byte key is auto-generated via CSPRNG at process startup.

### API

```cpp
#include "auth/jwt.hpp"
using namespace qbuem_routine;

// Issue access token (TTL: 24h)
std::string access_token = jwt::encode(claims);

// Issue refresh token (TTL: 30d)
std::string refresh_token = jwt::encode_refresh(claims);

// Verify access token + extract Claims (returns nullopt on expiry/signature/type mismatch)
std::optional<jwt::Claims> c = jwt::decode(token);

// Verify refresh token
std::optional<jwt::Claims> c = jwt::decode(token, jwt::TokenType::Refresh);

// Extract Bearer token from Authorization header
std::optional<std::string_view> t = jwt::extract_bearer(auth_header);
```

### Token Refresh Flow

```cpp
auto rc = jwt::decode(refresh_token, jwt::TokenType::Refresh);
if (!rc) { /* expired or tampered → request re-login */ }
std::string new_access = jwt::encode(*rc);
```

### Internal Implementation

```
token = base64url({"alg":"HS256","typ":"JWT"})
      . base64url(payload_json)
      . base64url(HMAC-SHA256(header.payload, secret))
```

- Signature verification: `qbuem::crypto::constant_time_equal()` (timing-safe)
- Payload includes `"type":"access"|"refresh"` field — type mismatch is rejected in `decode()`
- Base64url: no padding (`false`)

---

## HTTPS Client (`src/auth/https_client.hpp`)

Lightweight HTTPS client for low-frequency outbound requests such as OAuth token exchanges.

### Async Implementation Pattern

```
co_await https::post(url, body)
  │
  ├─ create eventfd
  ├─ std::thread::detach()  → OpenSSL BIO blocking I/O (Reactor thread non-blocking)
  │     └─ on complete: eventfd write(1)
  └─ EventFdAwaiter
        ├─ Reactor::register_event(efd, Read, ...)
        └─ completion event → Reactor::post(coroutine.resume())
```

Blocking OpenSSL calls run in a separate thread; completion is signalled to the Reactor via eventfd to resume the coroutine. The Reactor thread is never blocked.

### TLS Configuration

- `SSL_CTX_set_default_verify_paths()` — system CA bundle
- `SSL_VERIFY_PEER` — certificate verification enabled
- SNI support (`SSL_set_tlsext_host_name`)
- HTTP/1.1, `Connection: close`
- `ssl_init()` — thread-safe one-time initialization via `std::call_once`

### Response Struct

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

// POST (default Content-Type: application/x-www-form-urlencoded)
auto resp = co_await https::post(url, body);
auto resp = co_await https::post(url, body, "application/json");

// POST with extra headers
auto resp = co_await https::post(url, body,
    "application/x-www-form-urlencoded",
    "Authorization: Bearer token\r\n");

// GET
auto resp = co_await https::get(url);

// GET with extra headers
auto resp = co_await https::get(url, "Authorization: Bearer token\r\n");

if (resp.ok()) { /* resp.body ... */ }
```

### URL Parsing

Automatically parses `https://host[:port]/path?query` format. Default port: 443 (http: 80).

### Extra Headers Format

The `extra_headers` parameter is a concatenated string of headers, each terminated with `\r\n`:

```cpp
"Authorization: Bearer abc123\r\n"
"X-Custom-Header: value\r\n"
```

---

## OAuth2 (`src/auth/oauth.hpp`)

Google, Naver, Kakao, GitHub, Discord, Microsoft, and Facebook OAuth2 provider integrations.

### Auth Flow

```
1. GET /auth/{provider}/login
   └─ state = state_store::issue()
   └─ Provider::authorize_url(state)  →  302 redirect to provider

2. GET /auth/{provider}/callback?code=...&state=...
   ├─ Provider::exchange(code, state)
   │    ├─ state_store::verify_and_consume(state)  →  CSRF check (nullopt on failure)
   │    ├─ co_await https::post(token_endpoint, body)  →  access_token
   │    └─ co_await https::get(userinfo_endpoint, "Authorization: Bearer ...")  →  UserInfo
   └─  jwt::encode(Claims{...})  →  access token
       jwt::encode_refresh(Claims{...})  →  refresh token
```

### UserInfo Struct

```cpp
struct UserInfo {
    std::string provider;     // "google" | "naver" | "kakao" | ...
    std::string provider_id;  // Provider-scoped unique ID
    std::string email;
    std::string name;
    std::string avatar_url;
};
```

### Provider Endpoints

| Provider | Auth URL | Token Endpoint | Userinfo |
|----------|---------|----------------|---------|
| Google | accounts.google.com/o/oauth2/v2/auth | oauth2.googleapis.com/token | googleapis.com/oauth2/v3/userinfo |
| Naver | nid.naver.com/oauth2.0/authorize | nid.naver.com/oauth2.0/token | openapi.naver.com/v1/nid/me |
| Kakao | kauth.kakao.com/oauth/authorize | kauth.kakao.com/oauth/token | kapi.kakao.com/v2/user/me |
| GitHub | github.com/login/oauth/authorize | github.com/login/oauth/access_token | api.github.com/user |
| Discord | discord.com/api/oauth2/authorize | discord.com/api/oauth2/token | discord.com/api/users/@me |
| Microsoft | login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize | login.microsoftonline.com/{tenant}/oauth2/v2.0/token | graph.microsoft.com/v1.0/me |
| Facebook | facebook.com/v20.0/dialog/oauth | graph.facebook.com/v20.0/oauth/access_token | graph.facebook.com/v20.0/me |

### CSRF State Management

```cpp
// Issue state (TTL 10 min, in-memory)
std::string state = state_store::issue();

// Verify + consume (one-shot) — called automatically inside exchange()
bool ok = state_store::verify_and_consume(state);
```

- `qbuem::crypto::csrf_token(128)` — 128-bit CSPRNG URL-safe base64url token
- Thread-safe via `std::mutex`
- Expired entries are automatically cleaned up on `issue()`
- `verify_and_consume()` — verifies and deletes simultaneously (not reusable)

### Provider API

All `exchange()` functions accept a `state` parameter and perform CSRF verification internally.

```cpp
#include "auth/oauth.hpp"
using namespace qbuem_routine;

// Generate auth URL
auto state = oauth::state_store::issue();
std::string url = oauth::GoogleProvider::authorize_url(state);
std::string url = oauth::NaverProvider::authorize_url(state);
std::string url = oauth::KakaoProvider::authorize_url(state);
std::string url = oauth::GitHubProvider::authorize_url(state);
std::string url = oauth::DiscordProvider::authorize_url(state);
std::string url = oauth::MicrosoftProvider::authorize_url(state);
std::string url = oauth::FacebookProvider::authorize_url(state);

// Exchange code → UserInfo (includes state CSRF verification)
auto info = co_await oauth::GoogleProvider::exchange(code, state);    // optional<UserInfo>
auto info = co_await oauth::NaverProvider::exchange(code, state);
auto info = co_await oauth::KakaoProvider::exchange(code, state);
auto info = co_await oauth::GitHubProvider::exchange(code, state);
auto info = co_await oauth::DiscordProvider::exchange(code, state);
auto info = co_await oauth::MicrosoftProvider::exchange(code, state);
auto info = co_await oauth::FacebookProvider::exchange(code, state);
```

### Provider-Specific Notes

| Provider | Notes |
|----------|-------|
| **Google** | OIDC (openid+email+profile), userinfo via Authorization header |
| **Naver** | `state` included in token request (Naver spec), response unwrapped via `json_get_obj("response")` |
| **Kakao** | `id` field is integer (`"id":1234`), `kakao_account.profile` nested structure |
| **GitHub** | `User-Agent` header required, `Accept: application/json` on token request, falls back to `/user/emails` for private emails |
| **Discord** | Avatar URL assembled from `id + avatar_hash`, `global_name` → `username` fallback |
| **Microsoft** | Tenant-specific URL (`MICROSOFT_TENANT_ID`, default `common`), email from `mail` then `userPrincipalName` |
| **Facebook** | Token exchange via POST (non-standard), `picture.data.url` nested structure |

All providers pass userinfo API access tokens via `Authorization: Bearer` header, not URL parameters. (Facebook token exchange step is an exception.)

### Environment Variables

```
GOOGLE_CLIENT_ID,    GOOGLE_CLIENT_SECRET
NAVER_CLIENT_ID,     NAVER_CLIENT_SECRET
KAKAO_CLIENT_ID,     KAKAO_CLIENT_SECRET
GITHUB_CLIENT_ID,    GITHUB_CLIENT_SECRET
DISCORD_CLIENT_ID,   DISCORD_CLIENT_SECRET
MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET
MICROSOFT_TENANT_ID  (default: common — multi-tenant)
FACEBOOK_CLIENT_ID,  FACEBOOK_CLIENT_SECRET
OAUTH_REDIRECT_BASE  (e.g. https://your-domain.com, default: http://localhost:8080)
```

---

## Build

```bash
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_COMPILER=g++-13 \
      -DCMAKE_CXX_STANDARD=23 \
      -B build
cmake --build build
```

**Requirements**: GCC ≥ 13 / Clang ≥ 17, CMake ≥ 3.20, libssl-dev (OpenSSL)

---

## LLM Context Files

| File | Description |
|------|-------------|
| `llms.txt` | Core API summary (concise) |
| `llms_full.txt` | Full source code (detailed) |
