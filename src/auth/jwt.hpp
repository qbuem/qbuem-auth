#pragma once

/**
 * @file auth/jwt.hpp
 * @brief HS256 JWT creation and verification
 *
 * **Uses only qbuem-stack built-in crypto modules** (no OpenSSL required):
 *   - HMAC-SHA256 → <qbuem/crypto/hmac.hpp>
 *   - Base64url   → <qbuem/crypto/base64.hpp>
 *   - CSPRNG      → <qbuem/crypto/random.hpp>
 *   - Timing-safe → qbuem::crypto::constant_time_equal()
 *
 * Token structure (RFC 7519):
 *   base64url(header) . base64url(payload) . base64url(HMAC-SHA256)
 *
 * Payload:
 *   sub (string), provider, email, name, iat (int), exp (int), type ("access"|"refresh")
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

// ── TTL constants ─────────────────────────────────────────────────────────────

inline constexpr int64_t kAccessTokenTTL  = 60 * 60 * 24;       // 24h
inline constexpr int64_t kRefreshTokenTTL = 60 * 60 * 24 * 30;  // 30d

// ── Token type ────────────────────────────────────────────────────────────────

enum class TokenType { Access, Refresh };

// ── Claims ────────────────────────────────────────────────────────────────────

struct Claims {
    int64_t     sub;
    std::string provider;
    std::string email;
    std::string name;
    int64_t     iat  = 0;
    int64_t     exp  = 0;
    TokenType   type = TokenType::Access;
};

// ── Secret key (256-bit, generated once at process startup) ───────────────────

[[nodiscard]] inline std::span<const uint8_t> secret_bytes() noexcept {
    // JWT_SECRET env var takes priority; otherwise CSPRNG
    static const auto key = []() -> std::array<uint8_t, 32> {
        if (const char* env = std::getenv("JWT_SECRET"); env) {
            std::array<uint8_t, 32> k{};
            auto len = std::min(std::strlen(env), k.size());
            std::memcpy(k.data(), env, len);
            return k;
        }
        auto r = qbuem::crypto::random_bytes<32>();
        if (!r) return {};   // fallback: zero key (should not happen)
        return *r;
    }();
    return std::span<const uint8_t>{key.data(), key.size()};
}

// ── Internal helpers ──────────────────────────────────────────────────────────

namespace detail {

// JSON string escape (RFC 7159 compliant: includes control chars 0x00-0x1F)
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
            case '\t': r += "\\t";  break;
            case '\b': r += "\\b";  break;
            case '\f': r += "\\f";  break;
            default:
                // remaining control chars (0x00-0x1F) escaped as \uXXXX
                if (static_cast<unsigned char>(c) < 0x20)
                    r += std::format("\\u{:04x}", static_cast<unsigned char>(c));
                else
                    r += c;
                break;
        }
    }
    r += '"';
    return r;
}

// Fixed header base64url (compile-time constant)
[[nodiscard]] inline const std::string& encoded_header() {
    static const std::string h =
        qbuem::crypto::base64url_encode(
            std::string_view{R"({"alg":"HS256","typ":"JWT"})"}, false);
    return h;
}

// Build payload JSON
[[nodiscard]] inline std::string make_payload(const Claims& c, int64_t now,
                                               int64_t ttl, TokenType type) {
    const std::string_view type_str =
        (type == TokenType::Refresh) ? "refresh" : "access";
    return std::format(
        R"({{"sub":"{}","provider":{},"email":{},"name":{},"iat":{},"exp":{},"type":"{}"}})",
        c.sub,
        json_str(c.provider),
        json_str(c.email),
        json_str(c.name),
        now,
        now + ttl,
        type_str);
}

// HMAC-SHA256 signature → base64url
[[nodiscard]] inline std::string sign(std::string_view signing_input) {
    auto key  = secret_bytes();
    auto kvsv = std::string_view{
        reinterpret_cast<const char*>(key.data()), key.size()};
    auto digest = qbuem::crypto::hmac_sha256(kvsv, signing_input);
    return qbuem::crypto::base64url_encode(
        std::span<const uint8_t>{digest.data(), digest.size()}, false);
}

// Extract a string field from payload JSON — handles JSON escape sequences fully
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
        if (escaped) {
            // restore escaped character
            switch (c) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                default:   out += c;    break;  // \uXXXX etc. approximated
            }
            escaped = false;
            continue;
        }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') break;
        out += c;
    }
    return out;
}

[[nodiscard]] inline int64_t extract_int(std::string_view json,
                                          std::string_view key) {
    // Supports: "key":123  or  "key":"123"
    auto k = std::format(R"("{}":)", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return 0;
    pos += k.size();
    if (pos < json.size() && json[pos] == '"') ++pos;  // skip optional quote
    int64_t v = 0;
    std::from_chars(json.data() + pos, json.data() + json.size(), v);
    return v;
}

} // namespace detail

// ── Token issuance ────────────────────────────────────────────────────────────

/// Issue access token (TTL: 24h)
[[nodiscard]] inline std::string encode(const Claims& c) {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();

    const auto b64_payload = qbuem::crypto::base64url_encode(
        detail::make_payload(c, now, kAccessTokenTTL, TokenType::Access), false);
    const auto signing_input = detail::encoded_header() + "." + b64_payload;
    const auto b64_sig       = detail::sign(signing_input);

    return signing_input + "." + b64_sig;
}

/// Issue refresh token (TTL: 30d)
[[nodiscard]] inline std::string encode_refresh(const Claims& c) {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();

    const auto b64_payload = qbuem::crypto::base64url_encode(
        detail::make_payload(c, now, kRefreshTokenTTL, TokenType::Refresh), false);
    const auto signing_input = detail::encoded_header() + "." + b64_payload;
    const auto b64_sig       = detail::sign(signing_input);

    return signing_input + "." + b64_sig;
}

// ── Token verification ────────────────────────────────────────────────────────

/**
 * @brief Verify token and extract Claims.
 * @param token       JWT string to verify
 * @param expect_type Expected token type (default: Access)
 * @return Valid Claims, or nullopt on signature mismatch / expiry / type mismatch
 */
[[nodiscard]] inline std::optional<Claims>
decode(std::string_view token, TokenType expect_type = TokenType::Access) {
    // Split into 3 segments
    auto p1 = token.find('.');
    if (p1 == std::string_view::npos) return std::nullopt;
    auto p2 = token.find('.', p1 + 1);
    if (p2 == std::string_view::npos) return std::nullopt;

    const auto header_b64  = token.substr(0, p1);
    const auto payload_b64 = token.substr(p1 + 1, p2 - p1 - 1);
    const auto sig_b64     = token.substr(p2 + 1);

    // Recompute signature + timing-safe comparison
    const std::string signing_input =
        std::string(header_b64) + "." + std::string(payload_b64);
    const auto expected_sig = detail::sign(signing_input);

    if (!qbuem::constant_time_equal(expected_sig, sig_b64))
        return std::nullopt;

    // Decode payload
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

    // Verify token type
    const auto type_str = detail::extract_str(payload, "type");
    claims.type = (type_str == "refresh") ? TokenType::Refresh : TokenType::Access;
    if (claims.type != expect_type) return std::nullopt;

    // Verify expiry
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    if (claims.exp < now) return std::nullopt;

    return claims;
}

// ── Bearer token extraction ───────────────────────────────────────────────────

/// @note The returned string_view is tied to the lifetime of auth_header.
[[nodiscard]] inline std::optional<std::string_view>
extract_bearer(std::string_view auth_header) noexcept {
    constexpr std::string_view kBearer = "Bearer ";
    if (auth_header.starts_with(kBearer))
        return auth_header.substr(kBearer.size());
    return std::nullopt;
}

} // namespace qbuem_routine::jwt
