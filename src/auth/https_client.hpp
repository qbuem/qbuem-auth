#pragma once

/**
 * @file auth/https_client.hpp
 * @brief Lightweight HTTPS client (OpenSSL BIO + eventfd async wrapper)
 *
 * High-performance design:
 * - ThreadPool  : Reuses OS threads (no thread creation/destruction per request)
 * - ConnPool    : Reuses TLS sessions per host (eliminates handshake cost)
 *                 Connection: keep-alive + Content-Length based receive
 * - shared_ssl_ctx : SSL_CTX created once per process
 * - zero-copy body : Header removal via erase-front + move, no separate resp_body allocation
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

// ── Response struct ───────────────────────────────────────────────────────────

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

// ── Shared SSL_CTX singleton ──────────────────────────────────────────────────
// Created once per process. SSL_CTX is internally thread-safe.

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

// ── Thread pool ───────────────────────────────────────────────────────────────
// Fixed-size worker pool. Eliminates OS thread creation/destruction cost.

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

// ── Connection pool ───────────────────────────────────────────────────────────
// Stores and reuses TLS sessions per host. Automatically discards entries idle for more than 25s.
// keep-alive connections are returned to pool after Content-Length receive completes.

class ConnPool {
public:
    struct Entry {
        BIO*                                       bio;
        std::chrono::steady_clock::time_point      last_used;
    };

    static constexpr std::chrono::seconds kMaxIdle{25}; // Shorter than server keep-alive
    static constexpr size_t               kMaxPerHost{4};

    // Returns an available connection, or nullptr if none.
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
            BIO_free_all(e.bio);  // Idle timeout exceeded → discard
        }
        return nullptr;
    }

    // Returns a used connection to the pool. Discards if pool is full.
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

// ── Core HTTP request logic ───────────────────────────────────────────────────
// Accepts a BIO* and performs a single request.
// Returns: {Response, reusable}
//   reusable=true  → Read exactly via Content-Length, connection reusable
//   reusable=false → Read until EOF or error, connection discarded
// nullopt → Transmission failed (stale connection detected → triggers reconnect)

[[nodiscard]] inline std::optional<std::pair<Response, bool>>
do_request(BIO*             bio,
           std::string_view host,
           std::string_view method,
           std::string_view path,
           std::string_view req_body,
           std::string_view content_type,
           std::string_view extra_headers)
{
    // ── Send request ─────────────────────────────────────────────────────────
    std::string req = std::format("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);
    if (!req_body.empty()) {
        if (!content_type.empty())
            req += std::format("Content-Type: {}\r\n", content_type);
        req += std::format("Content-Length: {}\r\n", req_body.size());
    }
    if (!extra_headers.empty()) req += extra_headers;
    req += std::format("Connection: keep-alive\r\n\r\n{}", req_body);

    if (BIO_write(bio, req.data(), static_cast<int>(req.size())) <= 0)
        return std::nullopt;  // Transmission failed → stale connection
    BIO_flush(bio);

    // ── Receive response (up to header terminator \r\n\r\n) ──────────────────
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

// ── Connection lifecycle management ──────────────────────────────────────────
// Attempt reuse from pool → fall back to new connection → return or discard after completion

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

    // Connection management helper: after request, return to pool or discard based on result
    // nullopt(stale) → discard BIO, return false
    // ok + reusable  → return to pool, move Response
    // ok + !reusable → discard BIO, move Response
    auto try_conn = [&](BIO* bio) -> std::optional<Response> {
        auto res = do_request(bio, host, method, path, body, content_type, extra_headers);
        if (!res) { BIO_free_all(bio); return std::nullopt; }
        auto& [resp, reusable] = *res;
        if (reusable) pool.release(pool_key, bio);
        else          BIO_free_all(bio);
        return std::move(resp);
    };

    // 1. Attempt reuse from pool
    if (BIO* bio = pool.acquire(pool_key)) {
        if (auto resp = try_conn(bio)) return std::move(*resp);
        // try_conn returned nullopt → stale connection discarded, retry with new connection
    }

    // 2. New TLS connection
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

// ── URL parsing ───────────────────────────────────────────────────────────────

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

// ── Public async API ──────────────────────────────────────────────────────────
// Runs do_https() on a ThreadPool worker → signals completion via eventfd.
// Parameters: host/path are owned as std::string by parse_url(),
//             body/content_type/extra_headers are copied to std::string
//             (string_view parameters may dangle during co_await).

/**
 * @brief Asynchronous HTTPS POST request
 * @param url          Full URL (https://host/path?query)
 * @param body         Request body
 * @param content_type Content-Type header value
 * @param extra_headers Additional header string (each line must end with \r\n)
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
 * @brief Asynchronous HTTPS GET request
 * @param url          Full URL (https://host/path?query)
 * @param extra_headers Additional header string (each line must end with \r\n)
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
