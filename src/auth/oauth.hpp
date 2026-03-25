#pragma once

/**
 * @file auth/oauth.hpp
 * @brief OAuth2 provider integration
 *        — Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao
 *
 * Flow:
 *   1. GET /auth/{provider}/login  → 302 redirect to provider
 *   2. GET /auth/{provider}/callback?code=...&state=...
 *         → state CSRF verification → code exchange → user info fetch → JWT issuance
 *
 * Environment variable configuration:
 *   GOOGLE_CLIENT_ID,    GOOGLE_CLIENT_SECRET
 *   GITHUB_CLIENT_ID,    GITHUB_CLIENT_SECRET
 *   DISCORD_CLIENT_ID,   DISCORD_CLIENT_SECRET
 *   MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, MICROSOFT_TENANT_ID
 *   FACEBOOK_CLIENT_ID,  FACEBOOK_CLIENT_SECRET
 *   NAVER_CLIENT_ID,     NAVER_CLIENT_SECRET
 *   KAKAO_CLIENT_ID,     KAKAO_CLIENT_SECRET
 *   OAUTH_REDIRECT_BASE  (e.g. https://your-domain.com)
 */

#include "https_client.hpp"
#include "jwt.hpp"

#include <qbuem/core/task.hpp>
#include <qbuem/crypto.hpp>
#include <qbuem/url.hpp>          // qbuem::url_encode / url_decode

#include <array>
#include <chrono>
#include <format>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace qbuem_routine::oauth {

// ── User info (common across providers) ──────────────────────────────────────

struct UserInfo {
    std::string provider;     ///< google | github | discord | microsoft | facebook | naver | kakao
    std::string provider_id;  ///< Unique ID within the provider
    std::string email;
    std::string name;
    std::string avatar_url;
};

// ── Internal helpers ──────────────────────────────────────────────────────────

namespace detail {

// Query string parsing (key=val&key2=val2)
[[nodiscard]] inline std::unordered_map<std::string, std::string>
parse_query(std::string_view qs) {
    std::unordered_map<std::string, std::string> m;
    while (!qs.empty()) {
        auto amp  = qs.find('&');
        auto part = (amp == std::string_view::npos) ? qs : qs.substr(0, amp);
        auto eq   = part.find('=');
        if (eq != std::string_view::npos) {
            m[qbuem::url_decode(part.substr(0, eq))] =
              qbuem::url_decode(part.substr(eq + 1));
        }
        if (amp == std::string_view::npos) break;
        qs.remove_prefix(amp + 1);
    }
    return m;
}

// Zero-copy fast-path: returns string_view for string fields with no escape sequences.
// Returns empty view if field contains escapes or is absent (falls back to json_get_field).
// Lifetime of returned view matches the json parameter.
[[nodiscard]] inline std::string_view json_get_field_view(std::string_view json,
                                                           std::string_view key) {
    auto k = std::format(R"("{}":")", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return {};
    pos += k.size();
    auto start = pos;
    while (pos < json.size() && json[pos] != '"' && json[pos] != '\\')
        ++pos;
    if (pos >= json.size() || json[pos] == '\\') return {};  // escape or unterminated
    return json.substr(start, pos - start);
}

// Extracts a string field from JSON ("key":"val") — fully handles JSON escape sequences
// Also supports scalar fields ("key":123/true/null)
[[nodiscard]] inline std::string json_get_field(std::string_view json,
                                                 std::string_view key) {
    // ── String format: "key":"value" ─────────────────────────────────────────
    // Fast path: zero-copy view → string conversion for unescaped values
    if (auto v = json_get_field_view(json, key); !v.empty())
        return std::string{v};

    auto k_str = std::format(R"("{}":")", key);
    auto pos   = json.find(k_str);
    if (pos != std::string_view::npos) {
        pos += k_str.size();
        std::string out;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                ++pos;  // skip backslash
                switch (json[pos]) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    default:   out += json[pos]; break;  // \uXXXX etc. handled approximately
                }
            } else {
                out += json[pos];
            }
            ++pos;
        }
        return out;
    }

    // ── Scalar format: "key":value (number, boolean, null) ───────────────────
    auto k_int = std::format(R"("{}":)", key);
    pos = json.find(k_int);
    if (pos != std::string_view::npos) {
        pos += k_int.size();
        while (pos < json.size() && json[pos] == ' ') ++pos;  // skip leading spaces
        auto end = pos;
        while (end < json.size() && json[end] != ',' &&
               json[end] != '}' && json[end] != ']') {
            ++end;
        }
        // Trim trailing spaces
        while (end > pos && json[end - 1] == ' ') --end;
        auto val = json.substr(pos, end - pos);
        if (val == "null") return {};
        return std::string{val};
    }
    return {};
}

// Extracts a nested JSON object ("key":{ ... })
// Returns: string_view starting after the opening brace. Returns empty string_view if key absent.
// Note: does not fall back to returning the full json — prevents incorrect field matching
[[nodiscard]] inline std::string_view json_get_obj(std::string_view json,
                                                    std::string_view key) {
    auto k = std::format(R"("{}":{{)", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return {};  // key absent → return empty view
    return json.substr(pos + k.size());
}

inline std::string env_or(const char* name, std::string_view def = "") {
    if (const char* v = std::getenv(name); v && *v) return v;
    return std::string{def};
}

inline std::string redirect_base() {
    return env_or("OAUTH_REDIRECT_BASE", "http://localhost:8080");
}

} // namespace detail

// ── CSRF state management (in-memory, 10-minute TTL, sharded thread-safe) ────
// Shared by all providers, so must be declared before any provider definitions.
// Uses kShards independent mutexes instead of a single global mutex to distribute contention.

namespace state_store {

struct Entry { int64_t exp; };

namespace detail_ss {

inline constexpr size_t kShards = 16;

struct Shard {
    std::mutex                              mutex;
    std::unordered_map<std::string, Entry>  states;
};

// Shard array is an inline variable for ODR-safe global sharing
inline std::array<Shard, kShards> g_shards;

[[nodiscard]] inline Shard& shard_for(std::string_view key) {
    // Fast FNV-1a based hash (std::hash<string_view> is implementation-defined, so used directly)
    size_t h = 14695981039346656037ull;
    for (unsigned char c : key) h = (h ^ c) * 1099511628211ull;
    return g_shards[h % kShards];
}

inline void purge_expired_locked(Shard& shard, int64_t now) {
    for (auto it = shard.states.begin(); it != shard.states.end(); ) {
        if (it->second.exp < now) it = shard.states.erase(it);
        else ++it;
    }
}

} // namespace detail_ss

/// Issues a CSRF token (10-minute TTL). Automatically purges expired tokens in the shard.
inline std::string issue() {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    auto state = qbuem::csrf_token(128);

    auto& shard = detail_ss::shard_for(state);
    std::lock_guard lock{shard.mutex};
    detail_ss::purge_expired_locked(shard, now);
    shard.states[state] = {now + 600};
    return state;
}

/// Verifies and consumes the token (one-time use). Returns true only if valid and not expired.
inline bool verify_and_consume(std::string_view state) {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();

    auto& shard = detail_ss::shard_for(state);
    std::lock_guard lock{shard.mutex};
    auto it = shard.states.find(std::string{state});
    if (it == shard.states.end()) return false;
    bool valid = (it->second.exp >= now);
    shard.states.erase(it);
    return valid;
}

} // namespace state_store

// ═════════════════════════════════════════════════════════════════════════════
// Google OAuth2 (OIDC)
// ═════════════════════════════════════════════════════════════════════════════

struct GoogleProvider {
    static constexpr std::string_view kName = "google";

    [[nodiscard]] static std::string authorize_url(std::string_view state) {
        return std::format(
            "https://accounts.google.com/o/oauth2/v2/auth"
            "?client_id={}&redirect_uri={}&response_type=code"
            "&scope=openid+email+profile&state={}",
            qbuem::url_encode(detail::env_or("GOOGLE_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/google/callback"),
            qbuem::url_encode(state));
    }

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. Code → access token
        const std::string body = std::format(
            "code={}&client_id={}&client_secret={}"
            "&redirect_uri={}&grant_type=authorization_code",
            qbuem::url_encode(code),
            qbuem::url_encode(detail::env_or("GOOGLE_CLIENT_ID")),
            qbuem::url_encode(detail::env_or("GOOGLE_CLIENT_SECRET")),
            qbuem::url_encode(detail::redirect_base() + "/auth/google/callback"));

        auto token_resp = co_await https::post(
            "https://oauth2.googleapis.com/token", body);
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_field(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. User info
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://www.googleapis.com/oauth2/v3/userinfo", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;
        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = detail::json_get_field(j, "sub"),
            .email       = detail::json_get_field(j, "email"),
            .name        = detail::json_get_field(j, "name"),
            .avatar_url  = detail::json_get_field(j, "picture"),
        };
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// Naver Login (Korea-specific)
// ═════════════════════════════════════════════════════════════════════════════

struct NaverProvider {
    static constexpr std::string_view kName = "naver";

    [[nodiscard]] static std::string authorize_url(std::string_view state) {
        return std::format(
            "https://nid.naver.com/oauth2.0/authorize"
            "?client_id={}&redirect_uri={}&response_type=code&state={}",
            qbuem::url_encode(detail::env_or("NAVER_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/naver/callback"),
            qbuem::url_encode(state));
    }

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. Code → access token (Naver spec: state must also be included in token request)
        const std::string body = std::format(
            "grant_type=authorization_code&client_id={}&client_secret={}"
            "&code={}&state={}",
            qbuem::url_encode(detail::env_or("NAVER_CLIENT_ID")),
            qbuem::url_encode(detail::env_or("NAVER_CLIENT_SECRET")),
            qbuem::url_encode(code),
            qbuem::url_encode(state));

        auto token_resp = co_await https::post(
            "https://nid.naver.com/oauth2.0/token", body);
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_field(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. User info
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_raw = co_await https::get(
            "https://openapi.naver.com/v1/nid/me", auth_header);
        if (!info_raw.ok()) co_return std::nullopt;

        // Naver response: {"resultcode":"00","message":"success","response":{...}}
        const auto& j = info_raw.body;
        const auto resp_json = detail::json_get_obj(j, "response");
        if (resp_json.empty()) co_return std::nullopt;

        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = detail::json_get_field(resp_json, "id"),
            .email       = detail::json_get_field(resp_json, "email"),
            .name        = detail::json_get_field(resp_json, "name"),
            .avatar_url  = detail::json_get_field(resp_json, "profile_image"),
        };
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// Kakao Login (Korea-specific)
// ═════════════════════════════════════════════════════════════════════════════

struct KakaoProvider {
    static constexpr std::string_view kName = "kakao";

    [[nodiscard]] static std::string authorize_url(std::string_view state) {
        return std::format(
            "https://kauth.kakao.com/oauth/authorize"
            "?client_id={}&redirect_uri={}&response_type=code&state={}",
            qbuem::url_encode(detail::env_or("KAKAO_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/kakao/callback"),
            qbuem::url_encode(state));
    }

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. Code → access token
        const std::string body = std::format(
            "grant_type=authorization_code&client_id={}&redirect_uri={}&code={}",
            qbuem::url_encode(detail::env_or("KAKAO_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/kakao/callback"),
            qbuem::url_encode(code));

        auto token_resp = co_await https::post(
            "https://kauth.kakao.com/oauth/token", body);
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_field(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. User info
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://kapi.kakao.com/v2/user/me", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        // Kakao response structure:
        // {"id":1234,"kakao_account":{"email":"..","profile":{"nickname":"..","profile_image_url":".."}}}
        const auto& j = info_resp.body;

        // "id" is an integer field — json_get_field handles scalar format automatically
        const auto id = detail::json_get_field(j, "id");

        // Nested object access: kakao_account → profile
        // Missing kakao_account is an abnormal response — return nullopt
        auto acc_json  = detail::json_get_obj(j, "kakao_account");
        if (acc_json.empty()) co_return std::nullopt;

        // Missing profile is not fatal — name/avatar_url treated as empty strings
        auto prof_json = detail::json_get_obj(acc_json, "profile");
        std::string name, avatar_url;
        if (!prof_json.empty()) {
            name       = detail::json_get_field(prof_json, "nickname");
            avatar_url = detail::json_get_field(prof_json, "profile_image_url");
        }

        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = id,
            .email       = detail::json_get_field(acc_json, "email"),
            .name        = name,
            .avatar_url  = avatar_url,
        };
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// GitHub OAuth2
// ═════════════════════════════════════════════════════════════════════════════

struct GitHubProvider {
    static constexpr std::string_view kName = "github";

    [[nodiscard]] static std::string authorize_url(std::string_view state) {
        return std::format(
            "https://github.com/login/oauth/authorize"
            "?client_id={}&redirect_uri={}&scope=read:user+user:email&state={}",
            qbuem::url_encode(detail::env_or("GITHUB_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/github/callback"),
            qbuem::url_encode(state));
    }

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. Code → access token
        // GitHub returns form-encoded response without Accept: application/json
        const std::string body = std::format(
            "client_id={}&client_secret={}&code={}&redirect_uri={}",
            qbuem::url_encode(detail::env_or("GITHUB_CLIENT_ID")),
            qbuem::url_encode(detail::env_or("GITHUB_CLIENT_SECRET")),
            qbuem::url_encode(code),
            qbuem::url_encode(detail::redirect_base() + "/auth/github/callback"));

        auto token_resp = co_await https::post(
            "https://github.com/login/oauth/access_token", body,
            "application/x-www-form-urlencoded",
            "Accept: application/json\r\n");
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_field(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. User info
        // GitHub API requires User-Agent header and uses Authorization Bearer
        const std::string auth_header = std::format(
            "Authorization: Bearer {}\r\n"
            "Accept: application/vnd.github+json\r\n"
            "X-GitHub-Api-Version: 2022-11-28\r\n"
            "User-Agent: qbuem-auth\r\n",
            access_token);

        auto info_resp = co_await https::get("https://api.github.com/user", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;
        auto email = detail::json_get_field(j, "email");

        // If email is empty (null or private), fetch primary email from /user/emails
        if (email.empty()) {
            auto emails_resp = co_await https::get(
                "https://api.github.com/user/emails", auth_header);
            if (emails_resp.ok()) {
                // Extract email from the array entry with "primary":true
                const auto& ea = emails_resp.body;
                auto primary_pos = ea.find(R"("primary":true)");
                if (primary_pos != std::string::npos) {
                    auto obj_start = ea.rfind('{', primary_pos);
                    if (obj_start != std::string::npos)
                        email = detail::json_get_field(
                            std::string_view{ea}.substr(obj_start), "email");
                }
            }
        }

        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = detail::json_get_field(j, "id"),
            .email       = email,
            .name        = detail::json_get_field(j, "name"),
            .avatar_url  = detail::json_get_field(j, "avatar_url"),
        };
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// Discord OAuth2
// ═════════════════════════════════════════════════════════════════════════════

struct DiscordProvider {
    static constexpr std::string_view kName = "discord";

    [[nodiscard]] static std::string authorize_url(std::string_view state) {
        return std::format(
            "https://discord.com/api/oauth2/authorize"
            "?client_id={}&redirect_uri={}&response_type=code"
            "&scope=identify+email&state={}",
            qbuem::url_encode(detail::env_or("DISCORD_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/discord/callback"),
            qbuem::url_encode(state));
    }

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. Code → access token
        const std::string body = std::format(
            "client_id={}&client_secret={}&grant_type=authorization_code"
            "&code={}&redirect_uri={}",
            qbuem::url_encode(detail::env_or("DISCORD_CLIENT_ID")),
            qbuem::url_encode(detail::env_or("DISCORD_CLIENT_SECRET")),
            qbuem::url_encode(code),
            qbuem::url_encode(detail::redirect_base() + "/auth/discord/callback"));

        auto token_resp = co_await https::post(
            "https://discord.com/api/oauth2/token", body);
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_field(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. User info
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://discord.com/api/users/@me", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;
        const auto id     = detail::json_get_field(j, "id");
        const auto avatar = detail::json_get_field(j, "avatar");

        // Construct avatar URL: id + avatar hash → CDN URL
        std::string avatar_url;
        if (!avatar.empty())
            avatar_url = std::format(
                "https://cdn.discordapp.com/avatars/{}/{}.png", id, avatar);

        // Display name: prefer global_name, fall back to username
        auto name = detail::json_get_field(j, "global_name");
        if (name.empty())
            name = detail::json_get_field(j, "username");

        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = id,
            .email       = detail::json_get_field(j, "email"),
            .name        = name,
            .avatar_url  = avatar_url,
        };
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// Microsoft OAuth2 (Azure AD / Entra ID)
// ═════════════════════════════════════════════════════════════════════════════

struct MicrosoftProvider {
    static constexpr std::string_view kName = "microsoft";

    [[nodiscard]] static std::string authorize_url(std::string_view state) {
        const auto tenant = detail::env_or("MICROSOFT_TENANT_ID", "common");
        return std::format(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize"
            "?client_id={}&redirect_uri={}&response_type=code"
            "&scope=openid+email+profile+User.Read&state={}",
            tenant,
            qbuem::url_encode(detail::env_or("MICROSOFT_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/microsoft/callback"),
            qbuem::url_encode(state));
    }

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. Code → access token (tenant-specific endpoint)
        const auto tenant = detail::env_or("MICROSOFT_TENANT_ID", "common");
        const std::string body = std::format(
            "client_id={}&client_secret={}&grant_type=authorization_code"
            "&code={}&redirect_uri={}",
            qbuem::url_encode(detail::env_or("MICROSOFT_CLIENT_ID")),
            qbuem::url_encode(detail::env_or("MICROSOFT_CLIENT_SECRET")),
            qbuem::url_encode(code),
            qbuem::url_encode(detail::redirect_base() + "/auth/microsoft/callback"));

        const auto token_url = std::format(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant);
        auto token_resp = co_await https::post(token_url, body);
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_field(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. User info (Microsoft Graph API)
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://graph.microsoft.com/v1.0/me", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;

        // Email: try mail (Exchange) first, then userPrincipalName (personal account)
        auto email = detail::json_get_field(j, "mail");
        if (email.empty())
            email = detail::json_get_field(j, "userPrincipalName");

        // Graph API profile photo is returned as binary from /me/photo/$value.
        // No public URL exists, so the endpoint path is stored for the caller
        // to request directly with a Bearer token.
        const auto photo_meta_resp = co_await https::get(
            "https://graph.microsoft.com/v1.0/me/photo", auth_header);
        const std::string avatar_url = photo_meta_resp.ok()
            ? "https://graph.microsoft.com/v1.0/me/photo/$value"
            : std::string{};

        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = detail::json_get_field(j, "id"),
            .email       = email,
            .name        = detail::json_get_field(j, "displayName"),
            .avatar_url  = avatar_url,
        };
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// Facebook OAuth2 (Meta)
// ═════════════════════════════════════════════════════════════════════════════

struct FacebookProvider {
    static constexpr std::string_view kName = "facebook";

    [[nodiscard]] static std::string authorize_url(std::string_view state) {
        return std::format(
            "https://www.facebook.com/v20.0/dialog/oauth"
            "?client_id={}&redirect_uri={}&scope=email,public_profile&state={}",
            qbuem::url_encode(detail::env_or("FACEBOOK_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/facebook/callback"),
            qbuem::url_encode(state));
    }

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. Code → access token (using POST: keeps client_secret in body, not URL)
        // Using GET would expose client_secret in the URL, which may be logged by servers
        const std::string token_body = std::format(
            "client_id={}&client_secret={}&code={}&redirect_uri={}",
            qbuem::url_encode(detail::env_or("FACEBOOK_CLIENT_ID")),
            qbuem::url_encode(detail::env_or("FACEBOOK_CLIENT_SECRET")),
            qbuem::url_encode(code),
            qbuem::url_encode(detail::redirect_base() + "/auth/facebook/callback"));

        auto token_resp = co_await https::post(
            "https://graph.facebook.com/v20.0/oauth/access_token", token_body);
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_field(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. User info (explicit fields including picture)
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://graph.facebook.com/v20.0/me"
            "?fields=id,name,email,picture.type(large)",
            auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        // Profile picture nested structure: {"picture":{"data":{"url":"..."}}}
        // empty() guard applied at each level — missing picture yields empty avatar_url
        const auto& j = info_resp.body;
        std::string avatar_url;
        if (auto pic_data = detail::json_get_obj(j, "picture"); !pic_data.empty()) {
            if (auto pic_inner = detail::json_get_obj(pic_data, "data"); !pic_inner.empty())
                avatar_url = detail::json_get_field(pic_inner, "url");
        }

        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = detail::json_get_field(j, "id"),
            .email       = detail::json_get_field(j, "email"),
            .name        = detail::json_get_field(j, "name"),
            .avatar_url  = avatar_url,
        };
    }
};

} // namespace qbuem_routine::oauth
