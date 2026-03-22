#pragma once

/**
 * @file auth/oauth.hpp
 * @brief OAuth2 프로바이더 통합 — Google / Naver / Kakao (한국 특화)
 *
 * 흐름:
 *   1. GET /auth/{provider}/login  → 302 redirect to provider
 *   2. GET /auth/{provider}/callback?code=...&state=...
 *         → state CSRF 검증 → 코드 교환 → 사용자 정보 조회 → JWT 발급
 *
 * 환경변수 설정:
 *   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
 *   NAVER_CLIENT_ID,  NAVER_CLIENT_SECRET
 *   KAKAO_CLIENT_ID,  KAKAO_CLIENT_SECRET
 *   OAUTH_REDIRECT_BASE   (예: https://your-domain.com)
 */

#include "https_client.hpp"
#include "jwt.hpp"

#include <qbuem/core/task.hpp>
#include <qbuem/crypto.hpp>
#include <qbuem/url.hpp>          // qbuem::url_encode / url_decode

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
    std::string provider;     ///< google | naver | kakao
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

// JSON에서 필드 값 추출 — 문자열("key":"val")과 스칼라("key":123) 모두 지원
[[nodiscard]] inline std::string json_get_field(std::string_view json,
                                                 std::string_view key) {
    // 문자열 형식 "key":"value" 먼저 시도
    auto k_str = std::format(R"("{}":")", key);
    auto pos   = json.find(k_str);
    if (pos != std::string_view::npos) {
        pos += k_str.size();
        auto end = pos;
        while (end < json.size() && json[end] != '"') {
            if (json[end] == '\\') ++end;  // 이스케이프 문자 건너뜀
            ++end;
        }
        return std::string{json.substr(pos, end - pos)};
    }
    // 스칼라 형식 "key":value (숫자, boolean, null)
    auto k_int = std::format(R"("{}":)", key);
    pos = json.find(k_int);
    if (pos != std::string_view::npos) {
        pos += k_int.size();
        while (pos < json.size() && json[pos] == ' ') ++pos;  // 공백 건너뜀
        auto end = pos;
        while (end < json.size() && json[end] != ',' &&
               json[end] != '}' && json[end] != ']') {
            ++end;
        }
        auto val = json.substr(pos, end - pos);
        if (val == "null") return {};  // JSON null → 빈 문자열
        return std::string{val};
    }
    return {};
}

// 중첩 JSON 객체 내부 추출 ("key":{ ... })
// 반환값: { 이후 내용 (닫는 괄호 포함 안 함)
[[nodiscard]] inline std::string_view json_get_obj(std::string_view json,
                                                    std::string_view key) {
    auto k = std::format(R"("{}":{{)", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return json;  // fallback
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

// ── CSRF state 관리 (인메모리, TTL 10분, 스레드 안전) ────────────────────────
// 모든 프로바이더가 공유하므로 프로바이더 선언보다 먼저 위치해야 합니다.

namespace state_store {

struct Entry { int64_t exp; };
inline std::unordered_map<std::string, Entry> g_states;
inline std::mutex g_mutex;

// 만료된 엔트리 정리 (내부용, mutex 보유 상태에서 호출)
inline void purge_expired_locked(int64_t now) {
    for (auto it = g_states.begin(); it != g_states.end(); ) {
        if (it->second.exp < now) it = g_states.erase(it);
        else ++it;
    }
}

/// CSRF 토큰 발급 (TTL 10분). issue() 호출 시 만료 토큰 자동 정리.
inline std::string issue() {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    auto state = qbuem::crypto::csrf_token(128);

    std::lock_guard lock{g_mutex};
    purge_expired_locked(now);
    g_states[state] = {now + 600};
    return state;
}

/// 검증 + 소비 (1회용). 유효하고 만료되지 않은 경우에만 true.
inline bool verify_and_consume(std::string_view state) {
    using namespace std::chrono;
    const int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();

    std::lock_guard lock{g_mutex};
    auto it = g_states.find(std::string{state});
    if (it == g_states.end()) return false;
    bool valid = (it->second.exp >= now);
    g_states.erase(it);
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
            detail::env_or("GOOGLE_CLIENT_ID"),
            qbuem::url_encode(detail::redirect_base() + "/auth/google/callback"),
            state);
    }

    /// @param code  콜백으로 수신한 인가 코드
    /// @param state 콜백으로 수신한 state (CSRF 검증용)
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

        // 2. 사용자 정보 — Authorization: Bearer 헤더로 전달 (URL 노출 방지)
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_resp = co_await https::get(
            "https://www.googleapis.com/oauth2/v3/userinfo", auth_header);
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;
        co_return UserInfo{
            .provider    = "google",
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
            detail::env_or("NAVER_CLIENT_ID"),
            qbuem::url_encode(detail::redirect_base() + "/auth/naver/callback"),
            state);
    }

    /// @param code  콜백으로 수신한 인가 코드
    /// @param state 콜백으로 수신한 state (CSRF 검증 + Naver 토큰 요청용)
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

        // 2. 사용자 정보 — Authorization: Bearer 헤더로 전달 (URL 노출 방지)
        const std::string auth_header =
            std::format("Authorization: Bearer {}\r\n", access_token);
        auto info_raw = co_await https::get(
            "https://openapi.naver.com/v1/nid/me", auth_header);
        if (!info_raw.ok()) co_return std::nullopt;

        // Naver 응답: {"resultcode":"00","message":"success","response":{...}}
        const auto& j = info_raw.body;
        constexpr std::string_view kRespKey = R"("response":{)";
        auto resp_start = j.find(kRespKey);
        std::string_view resp_json = (resp_start != std::string::npos)
            ? std::string_view{j}.substr(resp_start + kRespKey.size())
            : std::string_view{j};

        co_return UserInfo{
            .provider    = "naver",
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
            detail::env_or("KAKAO_CLIENT_ID"),
            qbuem::url_encode(detail::redirect_base() + "/auth/kakao/callback"),
            state);
    }

    /// @param code  콜백으로 수신한 인가 코드
    /// @param state 콜백으로 수신한 state (CSRF 검증용)
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

        // 2. 사용자 정보 — Authorization: Bearer 헤더로 전달 (URL 노출 방지)
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
        auto acc_json  = detail::json_get_obj(j, "kakao_account");
        auto prof_json = detail::json_get_obj(acc_json, "profile");

        co_return UserInfo{
            .provider    = "kakao",
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
            detail::env_or("GITHUB_CLIENT_ID"),
            qbuem::url_encode(detail::redirect_base() + "/auth/github/callback"),
            state);
    }

    /// @param code  콜백으로 수신한 인가 코드
    /// @param state 콜백으로 수신한 state (CSRF 검증용)
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
            .provider    = "github",
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
            detail::env_or("DISCORD_CLIENT_ID"),
            qbuem::url_encode(detail::redirect_base() + "/auth/discord/callback"),
            state);
    }

    /// @param code  콜백으로 수신한 인가 코드
    /// @param state 콜백으로 수신한 state (CSRF 검증용)
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
            .provider    = "discord",
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
            detail::env_or("MICROSOFT_CLIENT_ID"),
            qbuem::url_encode(detail::redirect_base() + "/auth/microsoft/callback"),
            state);
    }

    /// @param code  콜백으로 수신한 인가 코드
    /// @param state 콜백으로 수신한 state (CSRF 검증용)
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

        co_return UserInfo{
            .provider    = "microsoft",
            .provider_id = detail::json_get_field(j, "id"),
            .email       = email,
            .name        = detail::json_get_field(j, "displayName"),
            .avatar_url  = {},  // Graph API 프로필 사진은 별도 /me/photo/$value 엔드포인트
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
            detail::env_or("FACEBOOK_CLIENT_ID"),
            qbuem::url_encode(detail::redirect_base() + "/auth/facebook/callback"),
            state);
    }

    /// @param code  콜백으로 수신한 인가 코드
    /// @param state 콜백으로 수신한 state (CSRF 검증용)
    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        if (!state_store::verify_and_consume(state)) co_return std::nullopt;

        // 1. 코드 → 액세스 토큰 (Facebook은 GET 방식 사용)
        const auto token_url = std::format(
            "https://graph.facebook.com/v20.0/oauth/access_token"
            "?client_id={}&client_secret={}&code={}&redirect_uri={}",
            qbuem::url_encode(detail::env_or("FACEBOOK_CLIENT_ID")),
            qbuem::url_encode(detail::env_or("FACEBOOK_CLIENT_SECRET")),
            qbuem::url_encode(code),
            qbuem::url_encode(detail::redirect_base() + "/auth/facebook/callback"));

        auto token_resp = co_await https::get(token_url);
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
        const auto& j = info_resp.body;
        auto pic_data    = detail::json_get_obj(j, "picture");
        auto pic_inner   = detail::json_get_obj(pic_data, "data");
        auto avatar_url  = detail::json_get_field(pic_inner, "url");

        co_return UserInfo{
            .provider    = "facebook",
            .provider_id = detail::json_get_field(j, "id"),
            .email       = detail::json_get_field(j, "email"),
            .name        = detail::json_get_field(j, "name"),
            .avatar_url  = avatar_url,
        };
    }
};

} // namespace qbuem_routine::oauth
