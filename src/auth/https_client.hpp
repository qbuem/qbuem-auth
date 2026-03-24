#pragma once

/**
 * @file auth/https_client.hpp
 * @brief 경량 HTTPS 클라이언트 (OpenSSL BIO + eventfd 비동기 래퍼)
 *
 * 고성능 설계:
 * - ThreadPool  : OS 스레드를 재사용 (요청마다 thread 생성·파괴 없음)
 * - ConnPool    : TLS 세션을 호스트별로 재사용 (핸드셰이크 비용 제거)
 *                 Connection: keep-alive + Content-Length 기반 수신
 * - shared_ssl_ctx : SSL_CTX 를 프로세스당 1회 생성
 * - zero-copy body : erase-front + move 로 헤더 제거, 별도 resp_body 할당 없음
 */

#include <qbuem/core/reactor.hpp>
#include <qbuem/core/task.hpp>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef __linux__
#  include <sys/eventfd.h>
#endif
#include <fcntl.h>
#include <unistd.h>

namespace qbuem_routine::https {

// ── 응답 구조체 ───────────────────────────────────────────────────────────────

struct Response {
    int         status = 0;
    std::string body;
    std::unordered_map<std::string, std::string> headers; ///< Lowercased header names → values

    bool ok() const noexcept { return status >= 200 && status < 300; }

    /**
     * @brief Case-insensitive header lookup.
     * @returns Header value, or empty string_view if absent.
     */
    std::string_view header(std::string_view key) const noexcept {
        char buf[64];
        const bool fits = key.size() < sizeof(buf);
        if (fits) {
            for (size_t i = 0; i < key.size(); ++i)
                buf[i] = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(key[i])));
            auto it = headers.find(std::string(std::string_view{buf, key.size()}));
            return (it != headers.end()) ? std::string_view{it->second}
                                         : std::string_view{};
        }
        std::string lower{key};
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        auto it = headers.find(lower);
        return (it != headers.end()) ? std::string_view{it->second}
                                     : std::string_view{};
    }
};

// ─────────────────────────────────────────────────────────────────────────────
namespace detail {

// ── SSL_CTX 공유 싱글톤 ───────────────────────────────────────────────────────
// 프로세스당 1회 생성. SSL_CTX는 내부적으로 스레드 안전.

[[nodiscard]] inline SSL_CTX* shared_ssl_ctx() {
    static SSL_CTX* ctx = []() -> SSL_CTX* {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        SSL_CTX* c = SSL_CTX_new(TLS_client_method());
        if (!c) return nullptr;
        SSL_CTX_set_default_verify_paths(c);
        SSL_CTX_set_verify(c, SSL_VERIFY_PEER, nullptr);
        return c;
    }();
    return ctx;
}

// ── 스레드 풀 ─────────────────────────────────────────────────────────────────
// 고정 크기 워커 풀. OS 스레드 생성·파괴 비용 제거.

class ThreadPool {
public:
    explicit ThreadPool(size_t n = std::max(2u, std::thread::hardware_concurrency())) {
        workers_.reserve(n);
        for (size_t i = 0; i < n; ++i)
            workers_.emplace_back([this] { run(); });
    }

    ~ThreadPool() {
        { std::lock_guard lock{mu_}; stop_ = true; }
        cv_.notify_all();
        for (auto& w : workers_) if (w.joinable()) w.join();
    }

    template<typename F>
    void submit(F&& f) {
        { std::lock_guard lock{mu_}; queue_.emplace(std::forward<F>(f)); }
        cv_.notify_one();
    }

    [[nodiscard]] static ThreadPool& global() {
        static ThreadPool pool;
        return pool;
    }

private:
    void run() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock lock{mu_};
                cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
                if (stop_ && queue_.empty()) return;
                task = std::move(queue_.front());
                queue_.pop();
            }
            task();
        }
    }

    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> queue_;
    std::mutex                        mu_;
    std::condition_variable           cv_;
    bool                              stop_ = false;
};

// ── 커넥션 풀 ─────────────────────────────────────────────────────────────────
// TLS 세션을 호스트별로 보관·재사용. 유휴 25초 초과 시 자동 폐기.
// keep-alive 연결은 Content-Length 수신 완료 후 반환.

class ConnPool {
public:
    struct Entry {
        BIO*                                       bio;
        std::chrono::steady_clock::time_point      last_used;
    };

    static constexpr std::chrono::seconds kMaxIdle{25}; // 서버 keep-alive보다 짧게
    static constexpr size_t               kMaxPerHost{4};

    // 사용 가능한 커넥션 반환. 없으면 nullptr.
    [[nodiscard]] BIO* acquire(std::string_view key) {
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock{mu_};
        auto it = pool_.find(std::string{key});
        if (it == pool_.end()) return nullptr;
        auto& vec = it->second;
        while (!vec.empty()) {
            Entry e = vec.back();
            vec.pop_back();
            if (now - e.last_used < kMaxIdle) return e.bio;
            BIO_free_all(e.bio);  // 유휴 시간 초과 → 폐기
        }
        return nullptr;
    }

    // 사용 완료된 커넥션 반환. 풀이 가득 찬 경우 폐기.
    void release(std::string_view key, BIO* bio) {
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock{mu_};
        auto& vec = pool_[std::string{key}];
        if (vec.size() < kMaxPerHost)
            vec.push_back({bio, now});
        else
            BIO_free_all(bio);
    }

    [[nodiscard]] static ConnPool& global() {
        static ConnPool pool;
        return pool;
    }

private:
    std::mutex                                         mu_;
    std::unordered_map<std::string, std::vector<Entry>> pool_;
};

// ── 핵심 HTTP 요청 로직 ───────────────────────────────────────────────────────
// BIO*를 받아 1회 요청 수행.
// 반환: {Response, reusable}
//   reusable=true  → Content-Length로 정확히 읽음, 커넥션 재사용 가능
//   reusable=false → EOF까지 읽음 or 오류, 커넥션 폐기
// nullopt → 전송 실패 (stale 커넥션 감지 → 재연결 트리거)

[[nodiscard]] inline std::optional<std::pair<Response, bool>>
do_request(BIO*             bio,
           std::string_view host,
           std::string_view method,
           std::string_view path,
           std::string_view req_body,
           std::string_view content_type,
           std::string_view extra_headers)
{
    // ── 요청 전송 ────────────────────────────────────────────────────────────
    std::string req = std::format("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);
    if (!req_body.empty()) {
        if (!content_type.empty())
            req += std::format("Content-Type: {}\r\n", content_type);
        req += std::format("Content-Length: {}\r\n", req_body.size());
    }
    if (!extra_headers.empty()) req += extra_headers;
    req += std::format("Connection: keep-alive\r\n\r\n{}", req_body);

    if (BIO_write(bio, req.data(), static_cast<int>(req.size())) <= 0)
        return std::nullopt;  // 전송 실패 → stale 커넥션
    BIO_flush(bio);

    // ── 응답 수신 (헤더 끝 \r\n\r\n 까지) ───────────────────────────────────
    std::string raw;
    raw.reserve(4096);
    char buf[4096];
    size_t sep = std::string::npos;
    while (sep == std::string::npos) {
        int n = BIO_read(bio, buf, sizeof(buf));
        if (n <= 0) return std::nullopt;
        raw.append(buf, static_cast<size_t>(n));
        sep = raw.find("\r\n\r\n");
    }

    // ── Status code parsing ──────────────────────────────────────────────────
    int status = 0;
    if (raw.starts_with("HTTP/")) {
        auto sp = raw.find(' ');
        if (sp != std::string::npos)
            std::from_chars(raw.data() + sp + 1, raw.data() + raw.size(), status);
    }

    // ── Parse response headers into map (skip status line) ──────────────────
    Response resp;
    resp.status = status;
    {
        std::string_view hdr_section{raw.data(), sep};
        auto nl = hdr_section.find("\r\n");     // skip status line
        if (nl != std::string_view::npos) {
            hdr_section.remove_prefix(nl + 2);
            while (!hdr_section.empty()) {
                auto line_end = hdr_section.find("\r\n");
                std::string_view line = (line_end != std::string_view::npos)
                    ? hdr_section.substr(0, line_end)
                    : hdr_section;
                auto colon = line.find(':');
                if (colon != std::string_view::npos) {
                    std::string key{line.substr(0, colon)};
                    std::transform(key.begin(), key.end(), key.begin(),
                        [](unsigned char c){ return std::tolower(c); });
                    std::string_view val = line.substr(colon + 1);
                    while (!val.empty() && (val[0] == ' ' || val[0] == '\t'))
                        val.remove_prefix(1);
                    resp.headers.emplace(std::move(key), std::string{val});
                }
                if (line_end == std::string_view::npos) break;
                hdr_section.remove_prefix(line_end + 2);
            }
        }
    }

    // ── Content-Length lookup via populated headers map ──────────────────────
    size_t content_length = std::string::npos;
    {
        auto it = resp.headers.find("content-length");
        if (it != resp.headers.end()) {
            size_t v = 0;
            std::from_chars(it->second.data(),
                            it->second.data() + it->second.size(), v);
            content_length = v;
        }
    }

    // ── Remove headers in-place; move remaining bytes into body ─────────────
    raw.erase(0, sep + 4);

    if (content_length != std::string::npos) {
        // Content-Length present: read exactly that many bytes; connection reusable
        while (raw.size() < content_length) {
            int n = BIO_read(bio, buf,
                static_cast<int>(std::min(sizeof(buf), content_length - raw.size())));
            if (n <= 0) break;
            raw.append(buf, static_cast<size_t>(n));
        }
        resp.body = std::move(raw);
        return std::pair{std::move(resp), true};
    } else {
        // No Content-Length: read until EOF (chunked or close); connection not reusable
        int n;
        while ((n = BIO_read(bio, buf, sizeof(buf))) > 0)
            raw.append(buf, static_cast<size_t>(n));
        resp.body = std::move(raw);
        return std::pair{std::move(resp), false};
    }
}

// ── 커넥션 생명주기 관리 ──────────────────────────────────────────────────────
// 풀에서 재사용 시도 → 실패 시 신규 연결 → 완료 후 풀 반환 or 폐기

[[nodiscard]] inline Response do_https(
    std::string_view host,
    uint16_t         port,
    std::string_view method,
    std::string_view path,
    std::string_view body,
    std::string_view content_type,
    std::string_view extra_headers)
{
    SSL_CTX* ctx = shared_ssl_ctx();
    if (!ctx) return {0, "SSL_CTX init failed", {}};

    const std::string pool_key = std::format("{}:{}", host, port);
    auto& pool = ConnPool::global();

    // 커넥션 관리 헬퍼: 요청 수행 후 결과에 따라 pool 반환 또는 폐기
    // nullopt(stale) → BIO 폐기, false 반환
    // ok + reusable  → pool 반환, Response 이동
    // ok + !reusable → BIO 폐기, Response 이동
    auto try_conn = [&](BIO* bio) -> std::optional<Response> {
        auto res = do_request(bio, host, method, path, body, content_type, extra_headers);
        if (!res) { BIO_free_all(bio); return std::nullopt; }
        auto& [resp, reusable] = *res;
        if (reusable) pool.release(pool_key, bio);
        else          BIO_free_all(bio);
        return std::move(resp);
    };

    // 1. 풀에서 재사용 시도
    if (BIO* bio = pool.acquire(pool_key)) {
        if (auto resp = try_conn(bio)) return std::move(*resp);
        // try_conn이 nullopt → stale 커넥션 폐기 완료, 신규 연결로 재시도
    }

    // 2. 신규 TLS 연결
    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) return {0, "BIO_new_ssl_connect failed", {}};

    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) { BIO_free_all(bio); return {0, "BIO_get_ssl failed", {}}; }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    const std::string host_str{host};
    SSL_set_tlsext_host_name(ssl, host_str.c_str());
    BIO_set_conn_hostname(bio, pool_key.c_str());

    if (BIO_do_connect(bio) <= 0 || BIO_do_handshake(bio) <= 0) {
        BIO_free_all(bio);
        return {0, "connect/handshake failed", {}};
    }

    if (auto resp = try_conn(bio)) return std::move(*resp);
    return {0, "request failed", {}};
}

// ── URL 파싱 ─────────────────────────────────────────────────────────────────

struct ParsedUrl {
    std::string host;
    uint16_t    port;
    std::string path;
};

[[nodiscard]] inline ParsedUrl parse_url(std::string_view url) {
    uint16_t port = 443;
    if (url.starts_with("https://"))      url.remove_prefix(8);
    else if (url.starts_with("http://")) { url.remove_prefix(7); port = 80; }

    auto slash = url.find('/');
    std::string host{url.substr(0, slash)};
    std::string path = (slash != std::string_view::npos)
        ? std::string{url.substr(slash)} : "/";

    if (auto colon = host.rfind(':'); colon != std::string::npos) {
        std::from_chars(host.data() + colon + 1, host.data() + host.size(), port);
        host.erase(colon);
    }
    return {std::move(host), port, std::move(path)};
}

} // namespace detail

// ── Platform-portable notification fd ────────────────────────────────────────
// Linux: eventfd (single fd, 8-byte counter)
// macOS: pipe pair (read_fd, write_fd)

namespace detail {

struct NotifyFd {
    int read_fd  = -1;  ///< Fd to register for EVFILT_READ / epoll read
    int write_fd = -1;  ///< Fd to write signal to (same as read_fd on Linux)

    static NotifyFd create() noexcept {
        NotifyFd n;
#ifdef __linux__
        n.read_fd = n.write_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
#else
        int fds[2];
        if (::pipe(fds) == 0) {
            ::fcntl(fds[0], F_SETFL, O_NONBLOCK | O_CLOEXEC);
            ::fcntl(fds[1], F_SETFL, O_NONBLOCK | O_CLOEXEC);
            n.read_fd  = fds[0];
            n.write_fd = fds[1];
        }
#endif
        return n;
    }

    bool valid() const noexcept { return read_fd >= 0; }

    void signal() const noexcept {
#ifdef __linux__
        uint64_t one = 1;
        [[maybe_unused]] auto _ = ::write(write_fd, &one, sizeof(one));
#else
        char one = 1;
        [[maybe_unused]] auto _ = ::write(write_fd, &one, sizeof(one));
#endif
    }

    void consume() const noexcept {
#ifdef __linux__
        uint64_t val = 0;
        [[maybe_unused]] auto _ = ::read(read_fd, &val, sizeof(val));
#else
        char val = 0;
        [[maybe_unused]] auto _ = ::read(read_fd, &val, sizeof(val));
#endif
    }

    void close_all() const noexcept {
        if (read_fd >= 0) ::close(read_fd);
#ifndef __linux__
        if (write_fd >= 0 && write_fd != read_fd) ::close(write_fd);
#endif
    }
};

} // namespace detail

// ── Notify Awaiter ────────────────────────────────────────────────────────────

struct EventFdAwaiter {
    detail::NotifyFd nfd;

    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto* reactor = qbuem::Reactor::current();
        reactor->register_event(nfd.read_fd, qbuem::EventType::Read,
            [this, h, reactor](int) mutable {
                reactor->unregister_event(nfd.read_fd, qbuem::EventType::Read);
                reactor->post([h]() mutable { h.resume(); });
            });
    }

    void await_resume() noexcept {
        nfd.consume();
    }
};

// ── 공개 비동기 API ────────────────────────────────────────────────────────────
// ThreadPool 워커에서 do_https() 실행 → eventfd로 완료 신호.
// 파라미터: host/path는 parse_url()이 std::string으로 소유,
//           body/content_type/extra_headers는 std::string으로 복사
//           (string_view 파라미터가 co_await 중에 댕글링될 수 있으므로).

/**
 * @brief 비동기 HTTPS POST 요청
 * @param url          전체 URL (https://host/path?query)
 * @param body         요청 바디
 * @param content_type Content-Type 헤더 값
 * @param extra_headers 추가 헤더 문자열 (각 줄 \r\n 으로 끝나야 함)
 */
[[nodiscard]] inline qbuem::Task<Response>
post(std::string_view url, std::string_view body,
     std::string_view content_type  = "application/x-www-form-urlencoded",
     std::string_view extra_headers = "")
{
    auto [host, port, path] = detail::parse_url(url);

    auto nfd = detail::NotifyFd::create();
    if (!nfd.valid()) co_return Response{0, "notify fd creation failed", {}};

    auto result = std::make_shared<Response>();
    detail::ThreadPool::global().submit([
        result,
        nfd,
        host   = std::move(host),
        port,
        path   = std::move(path),
        body   = std::string{body},
        ct     = std::string{content_type},
        hdrs   = std::string{extra_headers}
    ]() mutable {
        *result = detail::do_https(host, port, "POST", path, body, ct, hdrs);
        nfd.signal();
    });

    co_await EventFdAwaiter{nfd};
    nfd.close_all();
    co_return std::move(*result);
}

/**
 * @brief 비동기 HTTPS GET 요청
 * @param url          전체 URL (https://host/path?query)
 * @param extra_headers 추가 헤더 문자열 (각 줄 \r\n 으로 끝나야 함)
 */
[[nodiscard]] inline qbuem::Task<Response>
get(std::string_view url, std::string_view extra_headers = "")
{
    auto [host, port, path] = detail::parse_url(url);

    auto nfd = detail::NotifyFd::create();
    if (!nfd.valid()) co_return Response{0, "notify fd creation failed", {}};

    auto result = std::make_shared<Response>();
    detail::ThreadPool::global().submit([
        result,
        nfd,
        host = std::move(host),
        port,
        path = std::move(path),
        hdrs = std::string{extra_headers}
    ]() mutable {
        *result = detail::do_https(host, port, "GET", path, "", "", hdrs);
        nfd.signal();
    });

    co_await EventFdAwaiter{nfd};
    nfd.close_all();
    co_return std::move(*result);
}

} // namespace qbuem_routine::https
