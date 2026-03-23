#pragma once

/**
 * @file auth/oauth.hpp
 * @brief OAuth2 프로바이더 통합
 *        — Google / GitHub / Discord / Microsoft / Facebook / Naver / Kakao
 *
 * 흐름:
 *   1. GET /auth/{provider}/login  → 302 redirect to provider
 *   2. GET /auth/{provider}/callback?code=...&state=...
 *         → state CSRF 검증 → 코드 교환 → 사용자 정보 조회 → JWT 발급
 *
 * 환경변수 설정:
 *   GOOGLE_CLIENT_ID,    GOOGLE_CLIENT_SECRET
 *   GITHUB_CLIENT_ID,    GITHUB_CLIENT_SECRET
 *   DISCORD_CLIENT_ID,   DISCORD_CLIENT_SECRET
 *   MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, MICROSOFT_TENANT_ID
 *   FACEBOOK_CLIENT_ID,  FACEBOOK_CLIENT_SECRET
 *   NAVER_CLIENT_ID,     NAVER_CLIENT_SECRET
 *   KAKAO_CLIENT_ID,     KAKAO_CLIENT_SECRET
 *   OAUTH_REDIRECT_BASE  (예: https://your-domain.com)
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

// ── 사용자 정보 (프로바이더 공통) ────────────────────────────────────────────

struct UserInfo {
    std::string provider;     ///< google | github | discord | microsoft | facebook | naver | kakao
    std::string provider_id;  ///< 프로바이더 내 고유 ID
    std::string email;
    std::string name;
    std::string avatar_url;
};

// ── 내부 헬퍼 ────────────────────────────────────────────────────────────────

namespace detail {

// 쿼리 스트링 파싱 (key=val&key2=val2)
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

// Zero-copy fast-path: 이스케이프 시퀀스 없는 문자열 필드를 string_view로 반환.
// 이스케이프 포함이거나 필드가 없으면 빈 뷰 반환 (json_get_field로 fallback).
// 반환 뷰의 수명은 json 파라미터와 동일.
[[nodiscard]] inline std::string_view json_get_field_view(std::string_view json,
                                                           std::string_view key) {
    auto k = std::format(R"("{}":")", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return {};
    pos += k.size();
    auto start = pos;
    while (pos < json.size() && json[pos] != '"' && json[pos] != '\\')
        ++pos;
    if (pos >= json.size() || json[pos] == '\\') return {};  // 이스케이프 or 미종료
    return json.substr(start, pos - start);
}

// JSON에서 문자열 필드 추출 ("key":"val") — JSON 이스케이프 시퀀스 완전 처리
// 스칼라 필드 ("key":123/true/null)도 지원
[[nodiscard]] inline std::string json_get_field(std::string_view json,
                                                 std::string_view key) {
    // ── 문자열 형식: "key":"value" ──────────────────────────────────────────
    // Fast path: 이스케이프 없는 경우 zero-copy view → string 변환
    if (auto v = json_get_field_view(json, key); !v.empty())
        return std::string{v};

    auto k_str = std::format(R"("{}":")", key);
    auto pos   = json.find(k_str);
    if (pos != std::string_view::npos) {
        pos += k_str.size();
        std::string out;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                ++pos;  // 백슬래시 건너뜀
                switch (json[pos]) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    default:   out += json[pos]; break;  // \uXXXX 등은 근사 처리
                }
            } else {
                out += json[pos];
            }
            ++pos;
        }
        return out;
    }

    // ── 스칼라 형식: "key":value (숫자, boolean, null) ─────────────────────
    auto k_int = std::format(R"("{}":)", key);
    pos = json.find(k_int);
    if (pos != std::string_view::npos) {
        pos += k_int.size();
        while (pos < json.size() && json[pos] == ' ') ++pos;  // 선행 공백 제거
        auto end = pos;
        while (end < json.size() && json[end] != ',' &&
               json[end] != '}' && json[end] != ']') {
            ++end;
        }
        // 후행 공백 제거
        while (end > pos && json[end - 1] == ' ') --end;
        auto val = json.substr(pos, end - pos);
        if (val == "null") return {};
        return std::string{val};
    }
    return {};
}

// 중첩 JSON 객체 내부 추출 ("key":{ ... })
// 반환: { 다음 위치부터의 string_view. key가 없으면 빈 string_view 반환.
// ※ fallback으로 전체 json을 반환하지 않음 — 잘못된 필드 매칭 방지
[[nodiscard]] inline std::string_view json_get_obj(std::string_view json,
                                                    std::string_view key) {
    auto k = std::format(R"("{}":{{)", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return {};  // key 없으면 빈 뷰 반환
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

// ── CSRF state 관리 (인메모리, TTL 10분, 샤딩된 스레드 안전) ───────────────────
// 모든 프로바이더가 공유하므로 프로바이더 선언보다 먼저 위치해야 합니다.
// 단일 글로벌 mutex 대신 kShards개의 독립 mutex로 경합 분산.

namespace state_store {

struct Entry { int64_t exp; };

namespace detail_ss {

inline constexpr size_t kShards = 16;

struct Shard {
    std::mutex                              mutex;
    std::unordered_map<std::string, Entry>  states;
};

// 샤드 배열은 inline variable로 ODR-safe 전역 공유
inline std::array<Shard, kShards> g_shards;

[[nodiscard]] inline Shard& shard_for(std::string_view key) {
    // FNV-1a 기반 빠른 해시 (std::hash<string_view>는 구현 의존적이라 직접 사용)
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

/// CSRF 토큰 발급 (TTL 10분). 해당 샤드의 만료 토큰 자동 정리.
inline std::string issue() {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    auto state = qbuem::crypto::csrf_token(128);

    auto& shard = detail_ss::shard_for(state);
    std::lock_guard lock{shard.mutex};
    detail_ss::purge_expired_locked(shard, now);
    shard.states[state] = {now + 600};
    return state;
}

/// 검증 + 소비 (1회용). 유효하고 만료되지 않은 경우에만 true.
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

        // 1. 코드 → 액세스 토큰
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

        // 2. 사용자 정보
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
// Naver Login (한국 특화)
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

        // 1. 코드 → 액세스 토큰 (Naver 스펙: state를 토큰 요청에도 포함)
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

        // 2. 사용자 정보
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_raw = co_await https::get(
            "https://openapi.naver.com/v1/nid/me", auth_header);
        if (!info_raw.ok()) co_return std::nullopt;

        // Naver 응답: {"resultcode":"00","message":"success","response":{...}}
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
// Kakao Login (한국 특화)
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

        // 1. 코드 → 액세스 토큰
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

        // 2. 사용자 정보
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://kapi.kakao.com/v2/user/me", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        // 카카오 응답 구조:
        // {"id":1234,"kakao_account":{"email":"..","profile":{"nickname":"..","profile_image_url":".."}}}
        const auto& j = info_resp.body;

        // "id"는 정수 필드 — json_get_field가 스칼라 형식 자동 처리
        const auto id = detail::json_get_field(j, "id");

        // 중첩 객체 접근: kakao_account → profile
        // kakao_account 누락은 비정상 응답 — nullopt 반환
        auto acc_json  = detail::json_get_obj(j, "kakao_account");
        if (acc_json.empty()) co_return std::nullopt;
        auto prof_json = detail::json_get_obj(acc_json, "profile");

        co_return UserInfo{
            .provider    = std::string{kName},
            .provider_id = id,
            .email       = detail::json_get_field(acc_json, "email"),
            .name        = detail::json_get_field(prof_json, "nickname"),
            .avatar_url  = detail::json_get_field(prof_json, "profile_image_url"),
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

        // 1. 코드 → 액세스 토큰
        // GitHub은 Accept: application/json 없으면 form 인코딩으로 반환
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

        // 2. 사용자 정보
        // GitHub API는 User-Agent 헤더 필수, Authorization Bearer 사용
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

        // email이 비어 있으면 (null 또는 비공개) /user/emails에서 primary 이메일 조회
        if (email.empty()) {
            auto emails_resp = co_await https::get(
                "https://api.github.com/user/emails", auth_header);
            if (emails_resp.ok()) {
                // 배열 항목 중 "primary":true 인 객체의 email 추출
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

        // 1. 코드 → 액세스 토큰
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

        // 2. 사용자 정보
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://discord.com/api/users/@me", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;
        const auto id     = detail::json_get_field(j, "id");
        const auto avatar = detail::json_get_field(j, "avatar");

        // 아바타 URL 조합: id + avatar 해시 → CDN URL
        std::string avatar_url;
        if (!avatar.empty())
            avatar_url = std::format(
                "https://cdn.discordapp.com/avatars/{}/{}.png", id, avatar);

        // 표시 이름: global_name 우선, 없으면 username
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

        // 1. 코드 → 액세스 토큰 (테넌트별 엔드포인트)
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

        // 2. 사용자 정보 (Microsoft Graph API)
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://graph.microsoft.com/v1.0/me", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;

        // 이메일: mail (Exchange) 또는 userPrincipalName (개인 계정) 순서로 시도
        auto email = detail::json_get_field(j, "mail");
        if (email.empty())
            email = detail::json_get_field(j, "userPrincipalName");

        // Graph API 프로필 사진은 /me/photo/$value 에서 바이너리로 반환됨.
        // 공개 URL이 없으므로 엔드포인트 경로를 저장하여 호출자가 Bearer 토큰으로 직접 요청하도록 함.
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

        // 1. 코드 → 액세스 토큰 (POST 사용: client_secret을 URL이 아닌 바디에 포함)
        // GET으로 처리하면 client_secret이 URL에 노출되어 서버 로그 등에 기록됨
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

        // 2. 사용자 정보 (필요 필드 명시, picture 포함)
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://graph.facebook.com/v20.0/me"
            "?fields=id,name,email,picture.type(large)",
            auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        // 프로필 사진 중첩 구조: {"picture":{"data":{"url":"..."}}}
        // json_get_obj는 key 없으면 빈 뷰를 반환하므로 안전
        const auto& j = info_resp.body;
        auto pic_data   = detail::json_get_obj(j, "picture");
        auto pic_inner  = detail::json_get_obj(pic_data, "data");
        auto avatar_url = detail::json_get_field(pic_inner, "url");

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
