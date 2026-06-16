// Self-contained unit tests for qbuem-auth (no external framework).
// Covers the network-independent logic: JWT issue/verify, the shared JSON-string
// decoder, chunked transfer-decoding, URL parsing, OAuth query/JSON parsing and
// CSRF state store.  Network round-trips (provider exchange) are out of scope.
//
// Build:
//   clang++ -std=c++23 -I../src -I<qbuem-stack>/include -I<openssl>/include \
//           test_auth.cpp -o test_auth && ./test_auth

#include "auth/jwt.hpp"
#include "auth/oauth.hpp" // also pulls in https_client.hpp

#include <algorithm> // std::ranges::count
#include <cstdio>
#include <string>
#include <string_view>

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                            \
    do {                                                                      \
        ++g_total;                                                            \
        if (!(cond)) { ++g_fail; std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)
#define CHECK_EQ(a, b)                                                        \
    do {                                                                      \
        ++g_total;                                                            \
        auto _a = (a); auto _b = (b);                                         \
        if (!(_a == _b)) { ++g_fail; std::printf("FAIL %s:%d  (%s == %s)\n", __FILE__, __LINE__, #a, #b); } \
    } while (0)

namespace jwt   = qbuem_routine::jwt;
namespace https = qbuem_routine::https;
namespace oauth = qbuem_routine::oauth;

// ── JWT ──────────────────────────────────────────────────────────────────────
static void test_jwt() {
    jwt::Claims c{.sub = 42, .provider = "google", .email = "a@b.com",
                  .name = "Alice", .type = jwt::TokenType::Access};

    const std::string tok = jwt::encode(c);
    // 3 dot-separated segments
    CHECK(std::ranges::count(tok, '.') == 2);

    auto dec = jwt::decode(tok);
    CHECK(dec.has_value());
    if (dec) {
        CHECK_EQ(dec->sub, 42);
        CHECK_EQ(dec->provider, std::string("google"));
        CHECK_EQ(dec->email, std::string("a@b.com"));
        CHECK_EQ(dec->name, std::string("Alice"));
        CHECK(dec->exp > dec->iat);
    }

    // Tamper: flip a payload char → signature must reject.
    std::string bad = tok;
    auto p1 = bad.find('.');
    bad[p1 + 1] = (bad[p1 + 1] == 'A') ? 'B' : 'A';
    CHECK(!jwt::decode(bad).has_value());

    // Tamper: truncate signature.
    CHECK(!jwt::decode(tok.substr(0, tok.rfind('.'))).has_value());

    // Garbage / no segments.
    CHECK(!jwt::decode("not-a-token").has_value());
    CHECK(!jwt::decode("").has_value());

    // Token-type enforcement: access token must not verify as refresh.
    CHECK(!jwt::decode(tok, jwt::TokenType::Refresh).has_value());
    const std::string rtok = jwt::encode_refresh(c);
    CHECK(jwt::decode(rtok, jwt::TokenType::Refresh).has_value());
    CHECK(!jwt::decode(rtok, jwt::TokenType::Access).has_value());

    // Control-char name round-trips (make_payload \u-escapes it; decode restores).
    jwt::Claims c2{.sub = 1, .provider = "x", .email = "e",
                   .name = "a\nb\tc", .type = jwt::TokenType::Access};
    auto d2 = jwt::decode(jwt::encode(c2));
    CHECK(d2.has_value());
    if (d2) CHECK_EQ(d2->name, std::string("a\nb\tc"));

    // Bearer extraction.
    CHECK_EQ(jwt::extract_bearer("Bearer xyz").value_or("?"), std::string_view("xyz"));
    CHECK(!jwt::extract_bearer("Basic xyz").has_value());
}

// ── Shared JSON string decoder (\uXXXX + surrogate pairs) ─────────────────────
static void test_json_decoder() {
    using jwt::detail::decode_json_string_body;
    // pos points at first char after the opening quote.
    CHECK_EQ(decode_json_string_body(R"(hello")", 0), std::string("hello"));
    CHECK_EQ(decode_json_string_body(R"(a\nb")", 0), std::string("a\nb"));
    CHECK_EQ(decode_json_string_body(R"(AB")", 0), std::string("AB"));
    // Korean (U+D64D U+AE38 U+B3D9 "홍길동") via \u escapes.
    CHECK_EQ(decode_json_string_body(R"(홍길동")", 0),
             std::string("\xed\x99\x8d\xea\xb8\xb8\xeb\x8f\x99"));
    // Astral via surrogate pair → 😀 (U+1F600).
    CHECK_EQ(decode_json_string_body(R"(😀")", 0),
             std::string("\xf0\x9f\x98\x80"));
    // Lone surrogate → U+FFFD (always valid UTF-8).
    CHECK_EQ(decode_json_string_body(R"(\ud800")", 0), std::string("\xef\xbf\xbd"));
}

// ── Chunked transfer decoding ─────────────────────────────────────────────────
static void test_chunked() {
    using https::detail::decode_chunked;
    using https::detail::ChunkResult;
    std::string out;

    CHECK(decode_chunked("5\r\nhello\r\n0\r\n\r\n", out, 1 << 20) == ChunkResult::Complete);
    CHECK_EQ(out, std::string("hello"));

    // Two chunks.
    CHECK(decode_chunked("3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n", out, 1 << 20) == ChunkResult::Complete);
    CHECK_EQ(out, std::string("foobar"));

    // Chunk extension after ';' is ignored.
    CHECK(decode_chunked("5;x=1\r\nhello\r\n0\r\n\r\n", out, 1 << 20) == ChunkResult::Complete);
    CHECK_EQ(out, std::string("hello"));

    // Incomplete → NeedMore.
    CHECK(decode_chunked("5\r\nhel", out, 1 << 20) == ChunkResult::NeedMore);
    CHECK(decode_chunked("5\r\nhello\r\n", out, 1 << 20) == ChunkResult::NeedMore);

    // Bad hex → Error.
    CHECK(decode_chunked("zz\r\nhello\r\n0\r\n\r\n", out, 1 << 20) == ChunkResult::Error);

    // Body cap exceeded → Error.
    CHECK(decode_chunked("5\r\nhello\r\n0\r\n\r\n", out, 3) == ChunkResult::Error);
}

// ── URL parsing ───────────────────────────────────────────────────────────────
static void test_url() {
    using https::detail::parse_url;
    auto a = parse_url("https://example.com/path?q=1");
    CHECK_EQ(a.host, std::string("example.com"));
    CHECK_EQ(a.port, static_cast<uint16_t>(443));
    CHECK_EQ(a.path, std::string("/path?q=1"));

    auto b = parse_url("http://h.io:8080/p");
    CHECK_EQ(b.host, std::string("h.io"));
    CHECK_EQ(b.port, static_cast<uint16_t>(8080));
    CHECK_EQ(b.path, std::string("/p"));

    auto c = parse_url("https://host.only");
    CHECK_EQ(c.host, std::string("host.only"));
    CHECK_EQ(c.path, std::string("/"));
}

// ── Response header lookup (case-insensitive) ────────────────────────────────
static void test_response_header() {
    https::Response r;
    r.headers.emplace("content-type", "application/json");
    CHECK_EQ(r.header("Content-Type"), std::string_view("application/json"));
    CHECK_EQ(r.header("CONTENT-TYPE"), std::string_view("application/json"));
    CHECK(r.header("missing").empty());
}

// ── OAuth detail: query + JSON ────────────────────────────────────────────────
static void test_oauth_parsing() {
    auto q = oauth::detail::parse_query("code=abc&state=xyz");
    CHECK_EQ(q["code"], std::string("abc"));
    CHECK_EQ(q["state"], std::string("xyz"));

    using oauth::detail::json_get_field;
    using oauth::detail::json_get_obj;
    const std::string j = R"({"id":1234,"name":"Bob","email":"b@x.io","ok":true,"nil":null})";
    CHECK_EQ(json_get_field(j, "name"), std::string("Bob"));
    CHECK_EQ(json_get_field(j, "id"), std::string("1234"));   // scalar
    CHECK_EQ(json_get_field(j, "ok"), std::string("true"));
    CHECK_EQ(json_get_field(j, "nil"), std::string(""));      // null → empty
    CHECK_EQ(json_get_field(j, "absent"), std::string(""));

    // Nested object navigation.
    const std::string nested = R"({"response":{"id":"99","email":"n@n.io"}})";
    auto inner = json_get_obj(nested, "response");
    CHECK(!inner.empty());
    CHECK_EQ(json_get_field(inner, "id"), std::string("99"));

    // \u-escaped name in a provider response decodes correctly.
    const std::string ku = R"({"name":"홍길동"})";
    CHECK_EQ(json_get_field(ku, "name"),
             std::string("\xed\x99\x8d\xea\xb8\xb8\xeb\x8f\x99"));
}

// ── CSRF state store: one-time use ────────────────────────────────────────────
static void test_state_store() {
    namespace ss = oauth::state_store;
    const std::string s = ss::issue();
    CHECK(!s.empty());
    CHECK(ss::verify_and_consume(s));        // first use OK
    CHECK(!ss::verify_and_consume(s));        // replay rejected (consumed)
    CHECK(!ss::verify_and_consume("never-issued-token"));
}

int main() {
    test_jwt();
    test_json_decoder();
    test_chunked();
    test_url();
    test_response_header();
    test_oauth_parsing();
    test_state_store();
    std::printf("\n%d/%d checks passed\n", g_total - g_fail, g_total);
    return g_fail ? 1 : 0;
}
