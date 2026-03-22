#pragma once

/**
 * @file auth/jwt.hpp
 * @brief HS256 JWT 생성·검증
 *
 * **qbuem-stack 내장 암호 모듈만 사용** (OpenSSL 불필요):
 *   - HMAC-SHA256 → <qbuem/crypto/hmac.hpp>
 *   - Base64url   → <qbuem/crypto/base64.hpp>
 *   - CSPRNG      → <qbuem/crypto/random.hpp>
 *   - 타이밍 안전  → qbuem::crypto::constant_time_equal()
 *
 * 토큰 구조 (RFC 7519):
 *   base64url(header) . base64url(payload) . base64url(HMAC-SHA256)
 *
 * Payload:
 *   sub (string), provider, email, name, iat (int), exp (int)
 */

#include <qbuem/crypto/base64.hpp>
#include <qbuem/crypto/hmac.hpp>
#include <qbuem/crypto/random.hpp>
#include <qbuem/crypto.hpp>       // constant_time_equal

#include <charconv>
#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace qbuem_routine::jwt {

// ── 만료 기간 ────────────────────────────────────────────────────────────────

inline constexpr int64_t kAccessTokenTTL  = 60 * 60 * 24;       // 24h
inline constexpr int64_t kRefreshTokenTTL = 60 * 60 * 24 * 30;  // 30d

// ── Claims ────────────────────────────────────────────────────────────────────

struct Claims {
    int64_t     sub;
    std::string provider;
    std::string email;
    std::string name;
    int64_t     iat = 0;
    int64_t     exp = 0;
};

// ── 비밀 키 (256-bit, 프로세스 시작 시 1회 생성) ──────────────────────────────

[[nodiscard]] inline std::span<const uint8_t> secret_bytes() noexcept {
    // 환경변수 JWT_SECRET 우선, 없으면 CSPRNG
    static const auto key = []() -> std::array<uint8_t, 32> {
        if (const char* env = std::getenv("JWT_SECRET"); env) {
            std::array<uint8_t, 32> k{};
            auto len = std::min(std::strlen(env), k.size());
            std::memcpy(k.data(), env, len);
            return k;
        }
        return qbuem::crypto::random_bytes<32>();
    }();
    return std::span<const uint8_t>{key.data(), key.size()};
}

// ── 내부 헬퍼 ────────────────────────────────────────────────────────────────

namespace detail {

// JSON 문자열 이스케이프 (최소 필요 문자만)
[[nodiscard]] inline std::string json_str(std::string_view s) {
    std::string r;
    r.reserve(s.size() + 2);
    r += '"';
    for (char c : s) {
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            default:   r += c;
        }
    }
    r += '"';
    return r;
}

// 고정 헤더 base64url (컴파일 타임 상수)
[[nodiscard]] inline const std::string& encoded_header() {
    static const std::string h =
        qbuem::crypto::base64url_encode(
            std::string_view{R"({"alg":"HS256","typ":"JWT"})"}, false);
    return h;
}

// Payload JSON 생성
[[nodiscard]] inline std::string make_payload(const Claims& c, int64_t now) {
    return std::format(
        R"({{"sub":"{}","provider":{},"email":{},"name":{},"iat":{},"exp":{}}})",
        c.sub,
        json_str(c.provider),
        json_str(c.email),
        json_str(c.name),
        now,
        now + kAccessTokenTTL);
}

// HMAC-SHA256 서명 → base64url
[[nodiscard]] inline std::string sign(std::string_view signing_input) {
    auto key  = secret_bytes();
    auto kvsv = std::string_view{
        reinterpret_cast<const char*>(key.data()), key.size()};
    auto digest = qbuem::crypto::hmac_sha256(kvsv, signing_input);
    return qbuem::crypto::base64url_encode(
        std::span<const uint8_t>{digest.data(), digest.size()}, false);
}

// 페이로드 JSON에서 문자열 필드 추출 (경량 파서)
[[nodiscard]] inline std::string extract_str(std::string_view json,
                                              std::string_view key) {
    auto k = std::format(R"("{}":")", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return {};
    pos += k.size();
    std::string out;
    bool escaped = false;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (escaped) { out += c; escaped = false; continue; }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') break;
        out += c;
    }
    return out;
}

[[nodiscard]] inline int64_t extract_int(std::string_view json,
                                          std::string_view key) {
    // 지원 형식: "key":123  또는  "key":"123"
    auto k = std::format(R"("{}":)", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return 0;
    pos += k.size();
    if (pos < json.size() && json[pos] == '"') ++pos;  // 따옴표 건너뜀
    int64_t v = 0;
    std::from_chars(json.data() + pos, json.data() + json.size(), v);
    return v;
}

} // namespace detail

// ── 토큰 발급 ────────────────────────────────────────────────────────────────

[[nodiscard]] inline std::string encode(const Claims& c) {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();

    const auto b64_payload = qbuem::crypto::base64url_encode(
        detail::make_payload(c, now), false);
    const auto signing_input = detail::encoded_header() + "." + b64_payload;
    const auto b64_sig       = detail::sign(signing_input);

    return signing_input + "." + b64_sig;
}

// ── 토큰 검증 ────────────────────────────────────────────────────────────────

[[nodiscard]] inline std::optional<Claims> decode(std::string_view token) {
    // 3개 세그먼트 분리
    auto p1 = token.find('.');
    if (p1 == std::string_view::npos) return std::nullopt;
    auto p2 = token.find('.', p1 + 1);
    if (p2 == std::string_view::npos) return std::nullopt;

    const auto header_b64  = token.substr(0, p1);
    const auto payload_b64 = token.substr(p1 + 1, p2 - p1 - 1);
    const auto sig_b64     = token.substr(p2 + 1);

    // 서명 재계산 + 타이밍 안전 비교
    const std::string signing_input =
        std::string(header_b64) + "." + std::string(payload_b64);
    const auto expected_sig = detail::sign(signing_input);

    if (!qbuem::crypto::constant_time_equal(expected_sig, sig_b64))
        return std::nullopt;

    // Payload 복원
    auto payload_r = qbuem::crypto::base64url_decode(payload_b64);
    if (!payload_r) return std::nullopt;
    const std::string_view payload{*payload_r};

    Claims claims;
    claims.sub      = detail::extract_int(payload, "sub");
    claims.provider = detail::extract_str(payload, "provider");
    claims.email    = detail::extract_str(payload, "email");
    claims.name     = detail::extract_str(payload, "name");
    claims.iat      = detail::extract_int(payload, "iat");
    claims.exp      = detail::extract_int(payload, "exp");

    // 만료 확인
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    if (claims.exp < now) return std::nullopt;

    return claims;
}

// ── Bearer 토큰 추출 ─────────────────────────────────────────────────────────

[[nodiscard]] inline std::optional<std::string_view>
extract_bearer(std::string_view auth_header) noexcept {
    constexpr std::string_view kBearer = "Bearer ";
    if (auth_header.starts_with(kBearer))
        return auth_header.substr(kBearer.size());
    return std::nullopt;
}

} // namespace qbuem_routine::jwt
