#pragma once

/**
 * @file auth/https_client.hpp
 * @brief 경량 HTTPS 클라이언트 (OpenSSL BIO + eventfd 비동기 래퍼)
 *
 * OAuth 토큰 교환처럼 빈도가 낮은 아웃바운드 HTTPS 요청에 사용.
 * - 블로킹 OpenSSL 호출을 별도 std::thread 에서 실행
 * - eventfd 를 Reactor 에 등록하여 완료 시 코루틴 재개
 * - 리액터 스레드 블로킹 없음
 */

#include <qbuem/core/reactor.hpp>
#include <qbuem/core/task.hpp>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstring>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include <sys/eventfd.h>
#include <unistd.h>

namespace qbuem_routine::https {

// ── 응답 구조체 ───────────────────────────────────────────────────────────────

struct Response {
    int         status = 0;
    std::string body;
    bool        ok() const noexcept { return status >= 200 && status < 300; }
};

// ── OpenSSL 전역 초기화 (한 번만) ────────────────────────────────────────────

namespace detail {

inline void ssl_init() {
    static bool done = false;
    if (done) return;
    done = true;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

// ── 블로킹 HTTPS 요청 (별도 스레드에서 실행) ─────────────────────────────────

[[nodiscard]] inline Response do_https_blocking(
    std::string_view host,
    uint16_t         port,
    std::string_view method,
    std::string_view path,
    std::string_view body,
    std::string_view content_type)
{
    ssl_init();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return {0, "SSL_CTX_new failed"};
    // 인증서 검증 (시스템 CA 사용)
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    const std::string addr = std::format("{}:{}", host, port);
    BIO* bio = BIO_new_ssl_connect(ctx);
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    // SNI
    SSL_set_tlsext_host_name(ssl, std::string(host).c_str());
    BIO_set_conn_hostname(bio, addr.c_str());

    if (BIO_do_connect(bio) <= 0 || BIO_do_handshake(bio) <= 0) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return {0, "connect/handshake failed"};
    }

    // HTTP 요청 조합
    std::string req = std::format(
        "{} {} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{}",
        method, path, host, content_type, body.size(), body);

    BIO_write(bio, req.data(), static_cast<int>(req.size()));
    BIO_flush(bio);

    // 응답 수신
    std::string raw;
    raw.reserve(4096);
    char buf[4096];
    int  n;
    while ((n = BIO_read(bio, buf, sizeof(buf))) > 0)
        raw.append(buf, static_cast<size_t>(n));

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    // 상태 코드 파싱
    int status = 0;
    if (raw.starts_with("HTTP/")) {
        auto sp = raw.find(' ');
        if (sp != std::string::npos)
            std::from_chars(raw.data() + sp + 1,
                            raw.data() + raw.size(), status);
    }

    // 헤더와 바디 분리
    auto sep = raw.find("\r\n\r\n");
    std::string resp_body;
    if (sep != std::string::npos)
        resp_body = raw.substr(sep + 4);

    return {status, std::move(resp_body)};
}

} // namespace detail

// ── eventfd Awaiter ───────────────────────────────────────────────────────────

struct EventFdAwaiter {
    int efd;

    bool await_ready() const noexcept { return false; }

    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto* reactor = qbuem::Reactor::current();
        reactor->register_event(efd, qbuem::EventType::Read,
            [this, h, reactor](int) mutable {
                reactor->unregister_event(efd, qbuem::EventType::Read);
                reactor->post([h]() mutable { h.resume(); });
            });
    }

    void await_resume() noexcept {
        uint64_t val = 0;
        ::read(efd, &val, sizeof(val));
    }
};

// ── 공개 비동기 API ────────────────────────────────────────────────────────────

/**
 * @brief URL 파싱 후 비동기 HTTPS POST 요청
 * @param url         전체 URL (https://host/path?query)
 * @param body        요청 바디
 * @param content_type Content-Type 헤더 값
 */
[[nodiscard]] inline qbuem::Task<Response>
post(std::string_view url, std::string_view body,
     std::string_view content_type = "application/x-www-form-urlencoded")
{
    // URL 파싱 (host, port, path)
    std::string_view u = url;
    uint16_t port = 443;
    if (u.starts_with("https://")) u.remove_prefix(8);
    else if (u.starts_with("http://")) { u.remove_prefix(7); port = 80; }

    auto slash = u.find('/');
    std::string host{u.substr(0, slash)};
    std::string path = (slash != std::string_view::npos) ? std::string{u.substr(slash)} : "/";

    // 포트 오버라이드
    if (auto colon = host.rfind(':'); colon != std::string::npos) {
        std::from_chars(host.data() + colon + 1,
                        host.data() + host.size(), port);
        host.erase(colon);
    }

    // eventfd 생성
    int efd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    auto result = std::make_shared<Response>();
    std::string host_copy{host}, path_copy{path};
    std::string body_copy{body}, ct_copy{content_type};

    // 블로킹 작업을 별도 스레드에서 실행
    std::thread([=, result]() mutable {
        *result = detail::do_https_blocking(host_copy, port, "POST",
                                            path_copy, body_copy, ct_copy);
        uint64_t one = 1;
        ::write(efd, &one, sizeof(one));
    }).detach();

    // reactor 이벤트로 완료 대기
    co_await EventFdAwaiter{efd};
    ::close(efd);
    co_return *result;
}

/**
 * @brief 비동기 HTTPS GET 요청
 */
[[nodiscard]] inline qbuem::Task<Response>
get(std::string_view url)
{
    std::string_view u = url;
    uint16_t port = 443;
    if (u.starts_with("https://")) u.remove_prefix(8);
    else if (u.starts_with("http://")) { u.remove_prefix(7); port = 80; }

    auto slash = u.find('/');
    std::string host{u.substr(0, slash)};
    std::string path = (slash != std::string_view::npos) ? std::string{u.substr(slash)} : "/";

    if (auto colon = host.rfind(':'); colon != std::string::npos) {
        std::from_chars(host.data() + colon + 1,
                        host.data() + host.size(), port);
        host.erase(colon);
    }

    int efd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    auto result = std::make_shared<Response>();
    std::string h{host}, p{path};

    std::thread([=, result]() mutable {
        *result = detail::do_https_blocking(h, port, "GET", p, "", "");
        uint64_t one = 1;
        ::write(efd, &one, sizeof(one));
    }).detach();

    co_await EventFdAwaiter{efd};
    ::close(efd);
    co_return *result;
}

} // namespace qbuem_routine::https
