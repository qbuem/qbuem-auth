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

#include <charconv>
#include <cstring>
#include <format>
#include <memory>
#include <mutex>
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

// ── OpenSSL 전역 초기화 (한 번만, 스레드 안전) ───────────────────────────────

namespace detail {

// SSL_CTX 공유 싱글톤 — 프로세스당 1회 생성, 모든 요청이 재사용
// (zero-latency: 요청마다 SSL_CTX_new/free 비용 제거)
// SSL_CTX는 내부적으로 reference-counted BIO를 사용하므로 스레드 안전
inline SSL_CTX* shared_ssl_ctx() {
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

// ── 블로킹 HTTPS 요청 (별도 스레드에서 실행) ─────────────────────────────────

[[nodiscard]] inline Response do_https_blocking(
    std::string_view host,
    uint16_t         port,
    std::string_view method,
    std::string_view path,
    std::string_view body,
    std::string_view content_type,
    std::string_view extra_headers = "")
{
    SSL_CTX* ctx = shared_ssl_ctx();
    if (!ctx) return {0, "SSL_CTX init failed"};

    const std::string addr = std::format("{}:{}", host, port);

    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) return {0, "BIO_new_ssl_connect failed"};

    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        BIO_free_all(bio);
        return {0, "BIO_get_ssl failed"};
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // SNI: 임시 객체가 아닌 named string으로 전달 (포인터 유효성 보장)
    const std::string host_str{host};
    SSL_set_tlsext_host_name(ssl, host_str.c_str());
    BIO_set_conn_hostname(bio, addr.c_str());

    if (BIO_do_connect(bio) <= 0 || BIO_do_handshake(bio) <= 0) {
        BIO_free_all(bio);
        return {0, "connect/handshake failed"};
    }

    // HTTP 요청 조합
    std::string req = std::format(
        "{} {} HTTP/1.1\r\n"
        "Host: {}\r\n",
        method, path, host);

    // Content-Type / Content-Length는 바디가 있을 때만 전송
    // (GET 등 바디 없는 요청에 Content-Length: 0을 보내면 일부 서버가 거부)
    if (!body.empty()) {
        if (!content_type.empty())
            req += std::format("Content-Type: {}\r\n", content_type);
        req += std::format("Content-Length: {}\r\n", body.size());
    }

    if (!extra_headers.empty())
        req += extra_headers;

    req += std::format("Connection: close\r\n\r\n{}", body);

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
    // ctx는 공유 싱글톤이므로 해제하지 않음

    // 상태 코드 파싱
    int status = 0;
    if (raw.starts_with("HTTP/")) {
        auto sp = raw.find(' ');
        if (sp != std::string::npos)
            std::from_chars(raw.data() + sp + 1,
                            raw.data() + raw.size(), status);
    }

    // 헤더와 바디 분리 — substr 복사 대신 앞쪽 헤더를 in-place 제거 후 move
    // (zero-copy: raw 버퍼를 재사용, resp_body 별도 할당 없음)
    auto sep = raw.find("\r\n\r\n");
    if (sep != std::string::npos)
        raw.erase(0, sep + 4);
    else
        raw.clear();

    return {status, std::move(raw)};
}

// URL 파싱 (host, port, path) 공통 헬퍼
struct ParsedUrl {
    std::string host;
    uint16_t    port;
    std::string path;
};

[[nodiscard]] inline ParsedUrl parse_url(std::string_view url) {
    uint16_t port = 443;
    if (url.starts_with("https://")) url.remove_prefix(8);
    else if (url.starts_with("http://")) { url.remove_prefix(7); port = 80; }

    auto slash = url.find('/');
    std::string host{url.substr(0, slash)};
    std::string path = (slash != std::string_view::npos) ? std::string{url.substr(slash)} : "/";

    // 포트 오버라이드
    if (auto colon = host.rfind(':'); colon != std::string::npos) {
        std::from_chars(host.data() + colon + 1,
                        host.data() + host.size(), port);
        host.erase(colon);
    }

    return {std::move(host), port, std::move(path)};
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

    int efd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (efd < 0) co_return Response{0, "eventfd creation failed"};

    auto result = std::make_shared<Response>();
    std::string host_copy{host}, path_copy{path};
    std::string body_copy{body}, ct_copy{content_type};
    std::string hdrs_copy{extra_headers};

    // [=] 로 캡처: result(shared_ptr), efd, 문자열들 모두 값 복사
    // [=, result] 는 C++ 표준상 중복 캡처 오류이므로 [=] 사용
    std::thread([=]() mutable {
        *result = detail::do_https_blocking(host_copy, port, "POST",
                                            path_copy, body_copy, ct_copy, hdrs_copy);
        uint64_t one = 1;
        ::write(efd, &one, sizeof(one));
        // efd는 write 완료 후 코루틴이 close()하므로 여기서 닫지 않음
    }).detach();

    co_await EventFdAwaiter{efd};
    ::close(efd);
    co_return *result;
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

    int efd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (efd < 0) co_return Response{0, "eventfd creation failed"};

    auto result = std::make_shared<Response>();
    std::string h{host}, p{path}, hdrs{extra_headers};

    std::thread([=]() mutable {
        *result = detail::do_https_blocking(h, port, "GET", p, "", "", hdrs);
        uint64_t one = 1;
        ::write(efd, &one, sizeof(one));
    }).detach();

    co_await EventFdAwaiter{efd};
    ::close(efd);
    co_return *result;
}

} // namespace qbuem_routine::https
