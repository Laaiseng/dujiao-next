package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dujiao-next/internal/config"

	"github.com/gin-gonic/gin"
)

func TestResolveAllowedOrigin(t *testing.T) {
	got := resolveAllowedOrigin("https://example.com", []string{"*"}, false)
	if got != "*" {
		t.Fatalf("wildcard without credentials should return *, got %s", got)
	}

	got = resolveAllowedOrigin("https://example.com", []string{"*"}, true)
	if got != "" {
		t.Fatalf("wildcard with credentials must not echo origin, got %s", got)
	}

	got = resolveAllowedOrigin("https://a.example.com", []string{"https://a.example.com", "https://b.example.com"}, true)
	if got != "https://a.example.com" {
		t.Fatalf("allow-list should return matched origin, got %s", got)
	}

	got = resolveAllowedOrigin("https://x.example.com", []string{"https://a.example.com"}, true)
	if got != "" {
		t.Fatalf("unmatched origin should be empty, got %s", got)
	}

	got = resolveAllowedOrigin("https://evil.example\r\nX-Injected: 1", []string{"https://evil.example"}, true)
	if got != "" {
		t.Fatalf("origin with header injection must be rejected, got %q", got)
	}

	got = resolveAllowedOrigin("https://ai.luudan.xyz", []string{"https://AI.luudan.xyz"}, true)
	if got != "https://AI.luudan.xyz" {
		t.Fatalf("match should return the allowlisted value, got %s", got)
	}
}

func TestNormalizeCORSOriginsDropsWildcardWhenCredentialsEnabled(t *testing.T) {
	got, dropped := normalizeCORSOrigins([]string{"*"}, true)
	if !dropped {
		t.Fatal("wildcard with credentials must be dropped")
	}
	for _, origin := range got {
		if origin == "*" {
			t.Fatal("credentialed allowlist must not contain *")
		}
	}
	if !corsOriginListed(got, "https://ai.luudan.xyz") {
		t.Fatalf("wildcard-only config should fall back to the fixed production allowlist, got %v", got)
	}

	custom, dropped := normalizeCORSOrigins([]string{"*", "https://shop.example"}, true)
	if !dropped {
		t.Fatal("mixed wildcard should still be reported as dropped")
	}
	if len(custom) != 1 || custom[0] != "https://shop.example" {
		t.Fatalf("explicit origins must be kept without injecting defaults, got %#v", custom)
	}

	open, dropped := normalizeCORSOrigins([]string{"*"}, false)
	if dropped || len(open) != 1 || open[0] != "*" {
		t.Fatalf("wildcard without credentials should stay *, got %#v dropped=%v", open, dropped)
	}
}

func TestCORSMiddlewareUsesFixedAllowlistForPreflightAndActualRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func(cfg config.CORSConfig) *gin.Engine {
		r := gin.New()
		r.Use(CORSMiddleware(cfg))
		r.POST("/api/v1/auth/login", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status_code": 0})
		})
		return r
	}

	allow := config.CORSConfig{
		AllowedOrigins:   []string{"https://ai.luudan.xyz"},
		AllowedMethods:   []string{http.MethodPost, http.MethodOptions},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           600,
	}
	router := newRouter(allow)

	evilPreflight := serveCORS(router, http.MethodOptions, "https://evil.example")
	if evilPreflight.Code != http.StatusNoContent {
		t.Fatalf("evil preflight status = %d, want 204", evilPreflight.Code)
	}
	assertNoCredentialedCORS(t, evilPreflight, "https://evil.example")

	evilPost := serveCORS(router, http.MethodPost, "https://evil.example")
	if evilPost.Code != http.StatusOK {
		t.Fatalf("evil POST status = %d, want 200", evilPost.Code)
	}
	assertNoCredentialedCORS(t, evilPost, "https://evil.example")

	okPreflight := serveCORS(router, http.MethodOptions, "https://ai.luudan.xyz")
	if okPreflight.Code != http.StatusNoContent {
		t.Fatalf("allowlisted preflight status = %d, want 204", okPreflight.Code)
	}
	if got := okPreflight.Header().Get("Access-Control-Allow-Origin"); got != "https://ai.luudan.xyz" {
		t.Fatalf("allowlisted ACAO = %q", got)
	}
	if got := okPreflight.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("allowlisted credentials header = %q", got)
	}
	if !strings.Contains(okPreflight.Header().Get("Vary"), "Origin") {
		t.Fatal("allowlisted response should vary on Origin")
	}
	if !strings.Contains(okPreflight.Header().Get("Access-Control-Allow-Methods"), http.MethodPost) {
		t.Fatalf("preflight methods = %q", okPreflight.Header().Get("Access-Control-Allow-Methods"))
	}

	wildcard := newRouter(config.CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedMethods:   []string{http.MethodPost, http.MethodOptions},
		AllowedHeaders:   []string{"Content-Type"},
	})
	reflected := serveCORS(wildcard, http.MethodOptions, "https://evil.example")
	assertNoCredentialedCORS(t, reflected, "https://evil.example")
	if got := reflected.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatal("credentialed CORS must not answer with *")
	}
	listed := serveCORS(wildcard, http.MethodPost, "https://ai.luudan.xyz")
	if got := listed.Header().Get("Access-Control-Allow-Origin"); got != "https://ai.luudan.xyz" {
		t.Fatalf("wildcard config should fall back to the fixed allowlist, ACAO = %q", got)
	}
	if listed.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("fixed allowlist fallback should allow credentials for the production origin")
	}
}

func serveCORS(router http.Handler, method, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/auth/login", strings.NewReader(`{"email":"a@b.c"}`))
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func assertNoCredentialedCORS(t *testing.T, rec *httptest.ResponseRecorder, evilOrigin string) {
	t.Helper()
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin must not be reflected, ACAO = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("disallowed origin must not receive credential header, got %q", got)
	}
	for key, values := range rec.Header() {
		for _, value := range values {
			if strings.Contains(value, evilOrigin) || strings.Contains(key, evilOrigin) {
				t.Fatalf("response leaked evil origin in %s: %s", key, value)
			}
		}
	}
}

func corsOriginListed(origins []string, want string) bool {
	for _, origin := range origins {
		if origin == want {
			return true
		}
	}
	return false
}

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RequestIDMiddleware())
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"request_id": getRequestID(c)})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set(requestIDHeader, "req-123")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status want 200 got %d", w.Code)
	}
	if w.Header().Get(requestIDHeader) != "req-123" {
		t.Fatalf("response request id want req-123 got %s", w.Header().Get(requestIDHeader))
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}
	if resp["request_id"] != "req-123" {
		t.Fatalf("context request id want req-123 got %s", resp["request_id"])
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w2, req2)
	generated := w2.Header().Get(requestIDHeader)
	if generated == "" {
		t.Fatalf("generated request id should not be empty")
	}
	if resp := strings.TrimSpace(generated); resp == "" {
		t.Fatalf("generated request id should not be blank")
	}
}

func TestJWTAuthMiddlewareMissingSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(JWTAuthMiddleware("", nil))
	r.GET("/admin/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/ping", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status want 200 got %d", w.Code)
	}
	var resp struct {
		StatusCode int `json:"status_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status_code want 401 got %d", resp.StatusCode)
	}
}
