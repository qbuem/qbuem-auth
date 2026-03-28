# CLAUDE.md — qbuem-auth AI Context

This file provides structured context for AI coding assistants working in this repository.

---

## Language Policy

**All code, comments, documentation, and user-facing strings MUST be written in English.**

Korean or other non-English text in code comments, docs, or strings is a review failure.
Existing Korean comments in legacy files should be translated to English when touched.

---

## Project Overview

C++23 header-only authentication library.
HS256 JWT + lightweight async HTTPS client + 7 OAuth2 providers (Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao).

```
src/auth/
  jwt.hpp          — HS256 JWT signing and verification (qbuem::crypto only)
  https_client.hpp — OpenSSL BIO + eventfd Reactor async wrapper
  oauth.hpp        — OAuth2 providers with common UserInfo struct
```

---

## Design Goals: Zero-Copy · Zero-Latency

The current implementation prioritizes correctness and simplicity.
**High-performance versions should eliminate the copy points and latency sources listed below.**

---

## Zero-Copy: Current Status

### Applied

| Location | Detail |
|----------|--------|
| `detail::json_get_obj()` | Returns `std::string_view` — zero-copy parse result |
| `detail::json_get_field_view()` | Fast-path for unescaped string fields — zero-copy |
| `jwt::extract_bearer()` | Returns `std::optional<std::string_view>` — zero-copy header slice |
| `do_https()` arguments | All `std::string_view` — zero-copy call interface |
| `jwt::encoded_header()` | `static const std::string` — generated once, reused |
| `state_store::verify_and_consume()` | `std::string_view` argument |
| Response body header removal | `erase-front + move` — no separate `resp_body` allocation |
| `Response::headers` map | All response headers parsed and lowercased during `do_request()` |

### Remaining Copy Points (future work)

#### 1. `https::post()` / `https::get()` — defensive parameter copies (`https_client.hpp`)

```cpp
// Current: copied to std::string for detached thread hand-off
std::string host_copy{host}, path_copy{path};
```

**Root cause**: detached thread may outlive caller; `string_view` would dangle.
**High-perf alternative**: thread pool + `std::packaged_task` so the coroutine awaits while `string_view` stays valid.

#### 2. `do_https_blocking()` — double buffering

```cpp
// Current: stack buffer → raw(std::string) → resp_body(std::string)
char buf[4096];
std::string raw;
BIO_read(bio, buf, ...) → raw.append(...)  // copy 1
resp_body = raw.substr(sep + 4);           // copy 2
```

**Immediate improvement available**: replace `raw.substr(sep+4)` with `raw.erase(0, sep+4); return {status, std::move(raw)};`.

#### 3. `detail::json_get_field()` — heap allocation per field (`oauth.hpp`)

**High-perf alternative**: `string_view` fast-path when no escape sequences present.

#### 4. `UserInfo` — string copies from response body

**High-perf alternative**: `shared_ptr<std::string>` body owner + `string_view` fields.

#### 5. `jwt::extract_str()` — 5+ heap allocations per `decode()` call

**High-perf alternative**: `string_view` fields when no escape sequences in JWT payload.

---

## Zero-Latency: Current Status

### Applied

| Item | Detail |
|------|--------|
| `SSL_CTX` singleton | `SSL_CTX_new` called once per process |
| `ThreadPool` | `hardware_concurrency()` workers — no OS thread creation per request |
| `ConnPool` | Per-host TLS connection reuse (max 4, 25s idle timeout) |
| `Connection: keep-alive` | Eliminates per-request TCP setup |
| `state_store` sharded lock | 16-shard FNV-1a — eliminates global mutex contention |

### Remaining Latency Sources (future work)

- `authorize_url()` rebuilds URL on every call — `state` part only changes, rest can be cached.
- `json_get_field` pattern strings use `std::format` per call — replace with compile-time literals for known keys.

---

## Coding Rules

- **New provider**: define `kName` constant → use `.provider = std::string{kName}` in `exchange()` (no hard-coded strings).
- **`authorize_url()`**: `state` parameter must always go through `qbuem::url_encode(state)`.
- **`json_get_obj()` result**: always guard with `empty()` check before use.
- **Nested JSON**: chain `json_get_obj()` calls (see Naver/Kakao/Facebook patterns).
- **Header strings**: `"HeaderName: value\r\n"` format, trailing `\r\n` required.
- **Environment variables**: use `detail::env_or("KEY", "default")`.

---

## Response Struct

`https::Response` exposes status, body, and all response headers:

```cpp
struct Response {
    int         status = 0;
    std::string body;
    std::unordered_map<std::string, std::string> headers;  // keys lowercased

    bool ok() const noexcept { return status >= 200 && status < 300; }

    // Case-insensitive header lookup (keys already lowercased).
    std::string_view header(std::string_view key) const noexcept;
};
```

Usage:
```cpp
auto resp = co_await https::get(url);
auto retry_after = resp.header("retry-after");   // safe even if absent
auto content_type = resp.header("content-type");
```

---

## Known Limitations

- Chunked transfer encoding not supported — OAuth API responses are compact in practice.
- `json_get_obj()` does not bound object scope — false positives possible for same-named outer fields (no real-world impact on actual OAuth responses).
- `JWT_SECRET` truncated if > 32 bytes, zero-padded if < 32 bytes.
- Microsoft `avatar_url` requires Bearer token (`/me/photo/$value` endpoint).

---

## Dependencies

- **qbuem-stack**: `qbuem::crypto`, `qbuem::url_encode/decode`, `qbuem::Reactor`, `qbuem::Task<T>`
- **OpenSSL**: HTTPS outbound only (not used in JWT)

---

## Cross-Repo Guidelines

### Ecosystem Map

| Repo | Role | Key headers |
|------|------|-------------|
| **qbuem-stack** | Platform: async I/O, HTTP, pipelines, crypto, middleware | `<qbuem/http/*>`, `<qbuem/middleware/*>`, `<qbuem/crypto/*>` |
| **qbuem-auth** | Auth layer: JWT, HTTPS client, OAuth2 | `src/auth/jwt.hpp`, `src/auth/https_client.hpp`, `src/auth/oauth.hpp` |
| **qbuem-db** | DB layer: async drivers, ORM, migrations | `src/db/orm.hpp`, `src/db/*_driver.hpp` |
| **application repos** | WAS applications built on the above | depend on stack + auth + db; must not duplicate platform code |

### Filing Platform-Level Issues

When implementing a feature here requires functionality that belongs in a lower-level library,
**file an issue in the correct repo** rather than implementing it locally.

| Need | File issue at |
|------|--------------|
| New async primitive, protocol, or middleware | [qbuem-stack issues](https://github.com/qbuem/qbuem-stack/issues) |
| HTTPS client feature, JWT, OAuth provider | [qbuem-auth issues](https://github.com/qbuem/qbuem-auth/issues) |
| DB driver, ORM, migration feature | [qbuem-db issues](https://github.com/qbuem/qbuem-db/issues) |

If a temporary local workaround is necessary while waiting for an upstream fix, mark it:
```cpp
// TODO: remove after qbuem-auth#NNN is merged
```

> **Cross-repo development workflow and documentation update policy:**
> See root workspace CLAUDE.md at `/Users/goodboy/Projects/qbuem/CLAUDE.md`.
