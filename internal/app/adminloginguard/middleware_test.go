package adminloginguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestProtectRejectsBannedRequestWithoutIncrementOrHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	guard := newTestGuard(2)
	ctx := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", nil).Context()
	if _, err := guard.RecordFailure(ctx, "203.0.113.50", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RecordFailure(ctx, "203.0.113.50", ""); err != nil {
		t.Fatal(err)
	}
	before := guard.local.peek(guard.failKey(kindIP, "203.0.113.50"), guard.now())

	audits := 0
	handlerCalls := 0
	router := gin.New()
	router.POST("/api/v1/admin/login", Protect(guard, nil, func(_ *gin.Context, decision Decision) {
		audits++
		if decision.Username != "root" {
			t.Fatalf("username = %q", decision.Username)
		}
	}), func(c *gin.Context) {
		handlerCalls++
		c.Status(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", strings.NewReader(`{"username":"root","password":"secret"}`))
		req.RemoteAddr = "203.0.113.50:4321"
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
	}
	if handlerCalls != 0 {
		t.Fatalf("handler ran %d times", handlerCalls)
	}
	if audits != 1 {
		t.Fatalf("audit writes = %d, want 1", audits)
	}
	if got := guard.local.peek(guard.failKey(kindIP, "203.0.113.50"), guard.now()); got != before {
		t.Fatalf("counter changed from %d to %d", before, got)
	}
}

func TestProtectWhitelistSkipsRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	guard := newTestGuard(1, "203.0.113.60")
	rateLimitCalls := 0
	handlerCalls := 0
	router := gin.New()
	router.POST("/api/v1/admin/login", Protect(guard, func(c *gin.Context) {
		rateLimitCalls++
		c.Next()
	}, nil), func(c *gin.Context) {
		handlerCalls++
		if !WhitelistedFromContext(c) {
			t.Fatal("expected whitelist flag")
		}
		if ObservedFingerprint(c) != "" {
			t.Fatalf("invalid fingerprint was kept: %q", ObservedFingerprint(c))
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login", nil)
	req.RemoteAddr = "203.0.113.60:9"
	req.Header.Set(HeaderFingerprint, "not-a-fingerprint")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || handlerCalls != 1 || rateLimitCalls != 0 {
		t.Fatalf("status=%d handler=%d rate=%d", recorder.Code, handlerCalls, rateLimitCalls)
	}
}
