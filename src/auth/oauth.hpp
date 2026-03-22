#pragma once

/**
 * @file auth/oauth.hpp
 * @brief OAuth2 프로바이더 통합 — Google / Naver / Kakao (한국 특화)
 *
 * 흐름:
 *   1. GET /auth/{provider}/login  → 302 redirect to provider
 *   2. GET /auth/{provider}/callback?code=...&state=...
 *         → 코드 교환 → 사용자 정보 조회 → JWT 발급
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
#include <qbuem_json/qbuem_json.hpp>

#include <format>
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

// ── URL 인코딩/디코딩 — qbuem::url_encode / url_decode 위임 ──────────────────

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

// JSON에서 문자열 필드 추출 (간단 파서)
[[nodiscard]] inline std::string json_get_str(std::string_view json,
                                               std::string_view key) {
    auto k = std::format(R"("{}":")", key);
    auto pos = json.find(k);
    if (pos == std::string_view::npos) return {};
    pos += k.size();
    auto end = pos;
    // 이스케이프 처리
    while (end < json.size() && json[end] != '"') {
        if (json[end] == '\\') ++end;
        ++end;
    }
    return std::string{json.substr(pos, end - pos)};
}

inline std::string env_or(const char* name, std::string_view def = "") {
    if (const char* v = std::getenv(name); v && *v) return v;
    return std::string{def};
}

inline std::string redirect_base() {
    return env_or("OAUTH_REDIRECT_BASE", "http://localhost:8080");
}

} // namespace detail

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

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code) {
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

        const auto access_token = detail::json_get_str(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. 사용자 정보 조회
        auto info_resp = co_await https::get(
            "https://www.googleapis.com/oauth2/v3/userinfo"
            "?access_token=" + qbuem::url_encode(access_token));
        if (!info_resp.ok()) co_return std::nullopt;

        const auto& j = info_resp.body;
        co_return UserInfo{
            .provider    = "google",
            .provider_id = detail::json_get_str(j, "sub"),
            .email       = detail::json_get_str(j, "email"),
            .name        = detail::json_get_str(j, "name"),
            .avatar_url  = detail::json_get_str(j, "picture"),
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

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code, std::string_view state) {
        // 1. 코드 → 액세스 토큰
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

        const auto access_token = detail::json_get_str(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. 사용자 정보 (Authorization Bearer)
        // Naver userinfo는 GET + Authorization 헤더 필요 → https::get 확장 필요.
        // 여기서는 HTTPS GET을 직접 구성합니다.
        const std::string userinfo_url =
            "https://openapi.naver.com/v1/nid/me";
        auto info_raw = co_await https::get(
            userinfo_url + "?access_token=" + qbuem::url_encode(access_token));

        // Naver 응답: {"resultcode":"00","message":"success","response":{...}}
        const auto& j = info_raw.body;
        // response 객체 내부 추출
        auto resp_start = j.find(R"("response":{)");
        std::string resp_json;
        if (resp_start != std::string::npos) {
            resp_json = j.substr(resp_start + 12);
        }
        co_return UserInfo{
            .provider    = "naver",
            .provider_id = detail::json_get_str(resp_json.empty() ? j : resp_json, "id"),
            .email       = detail::json_get_str(resp_json.empty() ? j : resp_json, "email"),
            .name        = detail::json_get_str(resp_json.empty() ? j : resp_json, "name"),
            .avatar_url  = detail::json_get_str(resp_json.empty() ? j : resp_json, "profile_image"),
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

    [[nodiscard]] static qbuem::Task<std::optional<UserInfo>>
    exchange(std::string_view code) {
        // 1. 코드 → 액세스 토큰
        const std::string body = std::format(
            "grant_type=authorization_code&client_id={}&redirect_uri={}&code={}",
            qbuem::url_encode(detail::env_or("KAKAO_CLIENT_ID")),
            qbuem::url_encode(detail::redirect_base() + "/auth/kakao/callback"),
            qbuem::url_encode(code));

        auto token_resp = co_await https::post(
            "https://kauth.kakao.com/oauth/token", body);
        if (!token_resp.ok()) co_return std::nullopt;

        const auto access_token = detail::json_get_str(token_resp.body, "access_token");
        if (access_token.empty()) co_return std::nullopt;

        // 2. 사용자 정보
        auto info_resp = co_await https::get(
            "https://kapi.kakao.com/v2/user/me"
            "?access_token=" + qbuem::url_encode(access_token));
        if (!info_resp.ok()) co_return std::nullopt;

        // 카카오 응답 구조:
        // {"id":1234,"kakao_account":{"email":"..","profile":{"nickname":"..","profile_image_url":".."}}}
        const auto& j = info_resp.body;
        const auto id = detail::json_get_str(j, "id");

        auto acc_start = j.find(R"("kakao_account":{)");
        std::string acc_json = (acc_start != std::string::npos)
            ? j.substr(acc_start + 17) : j;

        auto prof_start = acc_json.find(R"("profile":{)");
        std::string prof_json = (prof_start != std::string::npos)
            ? acc_json.substr(prof_start + 11) : acc_json;

        co_return UserInfo{
            .provider    = "kakao",
            .provider_id = id,
            .email       = detail::json_get_str(acc_json, "email"),
            .name        = detail::json_get_str(prof_json, "nickname"),
            .avatar_url  = detail::json_get_str(prof_json, "profile_image_url"),
        };
    }
};

// ── CSRF state 관리 (인메모리, TTL 10분) ─────────────────────────────────────

namespace state_store {

struct Entry { std::string value; int64_t exp; };
inline std::unordered_map<std::string, Entry> g_states;

inline std::string issue() {
    using namespace std::chrono;
    auto state = qbuem::crypto::csrf_token(128);
    int64_t exp = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count() + 600;
    g_states[state] = {state, exp};
    return state;
}

inline bool verify_and_consume(std::string_view state) {
    using namespace std::chrono;
    auto it = g_states.find(std::string{state});
    if (it == g_states.end()) return false;
    int64_t now = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    bool valid = (it->second.exp >= now);
    g_states.erase(it);
    return valid;
}

} // namespace state_store

} // namespace qbuem_routine::oauth
