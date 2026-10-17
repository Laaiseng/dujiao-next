package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	userdomain "github.com/dujiao-next/internal/modules/identity/user/domain"
	userauthhttp "github.com/dujiao-next/internal/modules/identity/userauth/transport/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func TestKeyByIPAndJSONField(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(`{"email":" Test@Example.com "}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.RemoteAddr = "1.2.3.4:5678"

	key := KeyByIPAndJSONField("email")(c)
	if key != "test@example.com|1.2.3.4" {
		t.Fatalf("key want test@example.com|1.2.3.4 got %s", key)
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("read body after key extraction failed: %v", err)
	}
	if !strings.Contains(string(body), "Test@Example.com") {
		t.Fatalf("request body should be restored after reading field")
	}
}

func TestRateLimitMiddlewareWithoutClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RateLimitMiddleware(nil, RateLimitRule{WindowSeconds: 60, MaxRequests: 1}, KeyByIP))
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status want 200 got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("expected handler response body, got %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/ping", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request must be limited even without Redis: status want 429 got %d", w.Code)
	}
}

func TestLocalRateLimiterCapacityDoesNotEvictLiveEntries(t *testing.T) {
	now := time.Now()
	limiter := &localRateLimiter{entries: make(map[string]localRateLimitEntry, localRateLimitMaxEntries)}
	for i := 0; i < localRateLimitMaxEntries; i++ {
		limiter.entries[fmt.Sprintf("live-%d", i)] = localRateLimitEntry{
			count:     1,
			expiresAt: now.Add(10 * time.Minute),
		}
	}

	rule := RateLimitRule{WindowSeconds: 60, MaxRequests: 5}
	count, _, warned := limiter.increment("new-key", rule, now)
	if count <= int64(rule.MaxRequests) {
		t.Fatalf("new key must fail closed when local limiter is at capacity, count=%d", count)
	}
	if !warned {
		t.Fatal("first capacity rejection must request an operator warning")
	}
	_, _, warned = limiter.increment("another-new-key", rule, now.Add(time.Second))
	if warned {
		t.Fatal("capacity warning must be throttled")
	}
	_, _, warned = limiter.increment("later-new-key", rule, now.Add(localRateLimitWarningInterval))
	if !warned {
		t.Fatal("capacity warning should be emitted again after the throttle interval")
	}
	if len(limiter.entries) != localRateLimitMaxEntries {
		t.Fatalf("live entry count changed: got %d want %d", len(limiter.entries), localRateLimitMaxEntries)
	}
	if _, ok := limiter.entries["live-0"]; !ok {
		t.Fatal("capacity handling must not evict live counters")
	}
	if _, ok := limiter.entries["new-key"]; ok {
		t.Fatal("rejected new key must not be stored")
	}
}

func TestLocalRateLimiterPurgesExpiredEntriesBeforeRejectingNewKey(t *testing.T) {
	now := time.Now()
	limiter := &localRateLimiter{entries: make(map[string]localRateLimitEntry, localRateLimitMaxEntries)}
	for i := 0; i < localRateLimitMaxEntries; i++ {
		expiresAt := now.Add(time.Minute)
		if i == 0 {
			expiresAt = now.Add(-time.Second)
		}
		limiter.entries[fmt.Sprintf("entry-%d", i)] = localRateLimitEntry{
			count:     1,
			expiresAt: expiresAt,
		}
	}

	count, _, warned := limiter.increment("new-key", RateLimitRule{WindowSeconds: 60, MaxRequests: 5}, now)
	if count != 1 {
		t.Fatalf("new key count = %d, want 1 after expired entry cleanup", count)
	}
	if warned {
		t.Fatal("successful expired-entry cleanup must not emit a capacity warning")
	}
	if _, ok := limiter.entries["new-key"]; !ok {
		t.Fatal("new key should be stored after expired entry cleanup")
	}
	if _, ok := limiter.entries["entry-0"]; ok {
		t.Fatal("expired entry should be removed")
	}
}

func TestRateLimitMiddlewareFallsBackLocallyWhenRedisIsUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved address: %v", err)
	}
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		MaxRetries:   -1,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := gin.New()
	r.Use(RateLimitMiddleware(client, RateLimitRule{
		Prefix:        "redis-fallback-test",
		WindowSeconds: 60,
		MaxRequests:   1,
	}, KeyByIP))
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	first := httptest.NewRecorder()
	r.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first fallback request status = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	r.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second fallback request status = %d, want 429", second.Code)
	}
}

func TestToInt64(t *testing.T) {
	cases := []struct {
		name  string
		input interface{}
		want  int64
		ok    bool
	}{
		{name: "int64", input: int64(10), want: 10, ok: true},
		{name: "int", input: int(11), want: 11, ok: true},
		{name: "uint8", input: uint8(12), want: 12, ok: true},
		{name: "float64", input: float64(13.9), want: 13, ok: true},
		{name: "string", input: "bad", want: 0, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := toInt64(tc.input)
			if ok != tc.ok {
				t.Fatalf("ok want %v got %v", tc.ok, ok)
			}
			if got != tc.want {
				t.Fatalf("value want %d got %d", tc.want, got)
			}
		})
	}
}

func TestKeyByIPAndAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	emailReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":" User@Example.com ","password":"x","username":"other"}`))
	emailReq.RemoteAddr = "203.0.113.8:1000"
	emailCtx := newRateLimitContext(emailReq)
	if got := KeyByIPAndAccount(emailCtx); got != "user@example.com|203.0.113.8" {
		t.Fatalf("email key = %q", got)
	}
	body, err := io.ReadAll(emailCtx.Request.Body)
	if err != nil || !strings.Contains(string(body), "User@Example.com") {
		t.Fatalf("login body should stay readable, err=%v body=%s", err, body)
	}

	userReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":" Admin "}`))
	userReq.RemoteAddr = "203.0.113.9:1000"
	if got := KeyByIPAndAccount(newRateLimitContext(userReq)); got != "admin|203.0.113.9" {
		t.Fatalf("username key = %q", got)
	}
}

func TestUserLoginRateLimitRejectsCorrectPasswordUntilWindowRecovers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := &loginAuthStub{password: "correct-password"}
	router := newUserLoginRouter(RateLimitRule{
		Prefix:         "test:user_login:lock",
		WindowSeconds:  30,
		MaxRequests:    5,
		BlockSeconds:   2,
		MessageKey:     "error.login_too_many",
		ResetOnSuccess: true,
	}, auth)

	const (
		ip    = "203.0.113.10"
		email = "shopper@example.com"
	)
	for i := 0; i < 5; i++ {
		rec := postUserLogin(router, ip, email, "wrong-password")
		code, msg := decodeAPI(t, rec)
		if rec.Code != http.StatusOK || code != 401 {
			t.Fatalf("failure %d status/code = %d/%d body=%s", i+1, rec.Code, code, rec.Body.String())
		}
		if strings.Contains(msg, email) {
			t.Fatalf("failure message leaked the account: %s", msg)
		}
	}
	if auth.calls != 5 {
		t.Fatalf("auth calls after 5 failures = %d", auth.calls)
	}

	lockedCorrect := postUserLogin(router, ip, email, "correct-password")
	lockedWrong := postUserLogin(router, ip, email, "still-wrong")
	assertUniformLoginLockout(t, lockedCorrect, email)
	assertUniformLoginLockout(t, lockedWrong, email)
	if lockedCorrect.Body.String() != lockedWrong.Body.String() && !sameGenericLockout(lockedCorrect, lockedWrong) {
		t.Fatalf("locked responses diverged:\ncorrect=%s\nwrong=%s", lockedCorrect.Body.String(), lockedWrong.Body.String())
	}
	if auth.calls != 5 {
		t.Fatalf("locked requests must not check the password, calls=%d", auth.calls)
	}

	otherAccount := postUserLogin(router, ip, "other@example.com", "wrong-password")
	assertUniformLoginLockout(t, otherAccount, "other@example.com")
	if auth.calls != 5 {
		t.Fatalf("rotating the email on a locked IP must not check the password, calls=%d", auth.calls)
	}
	otherIP := postUserLogin(router, "203.0.113.11", email, "wrong-password")
	if code, _ := decodeAPI(t, otherIP); otherIP.Code != http.StatusOK || code != 401 {
		t.Fatalf("another IP must keep its own counter, status=%d body=%s", otherIP.Code, otherIP.Body.String())
	}

	deadline := time.Now().Add(5 * time.Second)
	var recovered *httptest.ResponseRecorder
	for {
		rec := postUserLogin(router, ip, email, "correct-password")
		code, _ := decodeAPI(t, rec)
		if rec.Code == http.StatusOK && code == 0 {
			recovered = rec
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("correct password stayed rejected after the block window, last status=%d body=%s", rec.Code, rec.Body.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(recovered.Body.String(), "ok-token") {
		t.Fatalf("recovered login body = %s", recovered.Body.String())
	}
	if auth.calls != 7 {
		t.Fatalf("auth calls = %d, want 5 failures + other IP + recovered success", auth.calls)
	}
}

func TestUserLoginRotatingEmailsHitIPAggregate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := &loginAuthStub{password: "correct-password"}
	router := newUserLoginRouter(RateLimitRule{
		Prefix:         "test:user_login:rotate",
		WindowSeconds:  300,
		MaxRequests:    5,
		BlockSeconds:   900,
		MessageKey:     "error.login_too_many",
		ResetOnSuccess: true,
	}, auth)

	const ip = "203.0.113.30"
	for i := 1; i <= 5; i++ {
		email := fmt.Sprintf("brute%d@example.com", i)
		rec := postUserLogin(router, ip, email, "wrong-password")
		code, msg := decodeAPI(t, rec)
		if rec.Code != http.StatusOK || code != 401 {
			t.Fatalf("email %d status/code = %d/%d body=%s", i, rec.Code, code, rec.Body.String())
		}
		if strings.Contains(msg, email) {
			t.Fatalf("failure message leaked the account: %s", msg)
		}
	}
	if auth.calls != 5 {
		t.Fatalf("auth calls after 5 rotating emails = %d", auth.calls)
	}

	blocked := postUserLogin(router, ip, "brute6@example.com", "correct-password")
	assertUniformLoginLockout(t, blocked, "brute6@example.com")
	if auth.calls != 5 {
		t.Fatalf("IP aggregate lock must skip the password check, calls=%d", auth.calls)
	}

	otherIP := postUserLogin(router, "203.0.113.31", "brute6@example.com", "wrong-password")
	if code, _ := decodeAPI(t, otherIP); otherIP.Code != http.StatusOK || code != 401 {
		t.Fatalf("another IP status=%d body=%s", otherIP.Code, otherIP.Body.String())
	}
	if auth.calls != 6 {
		t.Fatalf("other IP auth calls = %d", auth.calls)
	}
}

func TestUserLogin2FAChallengeClearsRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := &loginAuthStub{password: "correct-password", requireTOTP: true}
	router := newUserLoginRouter(RateLimitRule{
		Prefix:         "test:user_login:totp",
		WindowSeconds:  300,
		MaxRequests:    5,
		BlockSeconds:   900,
		MessageKey:     "error.login_too_many",
		ResetOnSuccess: true,
	}, auth)

	const (
		ip    = "203.0.113.32"
		email = "totp@example.com"
	)
	for i := 0; i < 4; i++ {
		rec := postUserLogin(router, ip, email, "wrong-password")
		code, _ := decodeAPI(t, rec)
		if rec.Code != http.StatusOK || code != 401 {
			t.Fatalf("failure %d body=%s", i+1, rec.Body.String())
		}
	}
	challenge := postUserLogin(router, ip, email, "correct-password")
	code, _ := decodeAPI(t, challenge)
	if challenge.Code != http.StatusOK || code != 0 || !strings.Contains(challenge.Body.String(), `"requires_totp":true`) {
		t.Fatalf("2FA challenge body=%s", challenge.Body.String())
	}
	calls := auth.calls
	again := postUserLogin(router, ip, "other-after-totp@example.com", "wrong-password")
	againCode, _ := decodeAPI(t, again)
	if again.Code != http.StatusOK || againCode != 401 {
		t.Fatalf("IP counter should clear when the password step returns a 2FA challenge, status=%d body=%s", again.Code, again.Body.String())
	}
	if auth.calls != calls+1 {
		t.Fatalf("auth calls after cleared failure = %d, want %d", auth.calls, calls+1)
	}
}

func TestUserLoginSuccessClearsRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := &loginAuthStub{password: "correct-password"}
	router := newUserLoginRouter(RateLimitRule{
		Prefix:         "test:user_login:clear",
		WindowSeconds:  30,
		MaxRequests:    5,
		BlockSeconds:   30,
		MessageKey:     "error.login_too_many",
		ResetOnSuccess: true,
	}, auth)

	for i := 0; i < 4; i++ {
		rec := postUserLogin(router, "203.0.113.20", "clear@example.com", "wrong-password")
		code, _ := decodeAPI(t, rec)
		if rec.Code != http.StatusOK || code != 401 {
			t.Fatalf("failure %d body=%s", i+1, rec.Body.String())
		}
	}
	success := postUserLogin(router, "203.0.113.20", "clear@example.com", "correct-password")
	if code, _ := decodeAPI(t, success); success.Code != http.StatusOK || code != 0 {
		t.Fatalf("success body=%s", success.Body.String())
	}
	calls := auth.calls
	again := postUserLogin(router, "203.0.113.20", "clear@example.com", "wrong-password")
	code, msg := decodeAPI(t, again)
	if again.Code != http.StatusOK || code != 401 {
		t.Fatalf("failure after success should be counted fresh, status=%d code=%d msg=%s", again.Code, code, msg)
	}
	if auth.calls != calls+1 {
		t.Fatalf("auth calls after cleared failure = %d, want %d", auth.calls, calls+1)
	}
}

type loginSettingsStub struct{}

func (loginSettingsStub) GetRegistrationEnabled(bool) (bool, error) { return true, nil }

func (loginSettingsStub) GetEmailVerificationEnabled(bool) (bool, error) { return false, nil }

type loginAuthStub struct {
	password    string
	calls       int
	requireTOTP bool
}

func (s *loginAuthStub) Register(context.Context, string, string, string, string, bool, bool) (*userdomain.User, string, time.Time, error) {
	return nil, "", time.Time{}, context.Canceled
}

func (s *loginAuthStub) LoginStep1(_ context.Context, email, password string, _ bool) (*userauthhttp.AuthLoginResult, error) {
	s.calls++
	if password != s.password {
		return nil, userauthhttp.ErrInvalidCredentials
	}
	result := &userauthhttp.AuthLoginResult{
		User:      &userdomain.User{ID: 1, Email: email, DisplayName: "tester"},
		Token:     "ok-token",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if s.requireTOTP {
		result.RequiresTOTP = true
		result.Token = ""
		result.ChallengeToken = "challenge-token"
		result.ChallengeExpiresAt = time.Now().Add(5 * time.Minute)
	}
	return result, nil
}

func newUserLoginRouter(rule RateLimitRule, auth *loginAuthStub) *gin.Engine {
	handler := userauthhttp.NewUserLoginHandler(loginSettingsStub{}, auth, nil, nil)
	router := gin.New()
	userauthhttp.RegisterUserLoginAuthRoutes(
		router.Group("/api/v1/auth"),
		handler,
		RateLimitMiddlewareKeys(nil, rule, KeyByIP, KeyByIPAndAccount),
	)
	return router
}

func newRateLimitContext(req *http.Request) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c
}

func postUserLogin(router http.Handler, ip, email, password string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1000"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeAPI(t *testing.T, rec *httptest.ResponseRecorder) (int, string) {
	t.Helper()
	var payload struct {
		StatusCode int    `json:"status_code"`
		Msg        string `json:"msg"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	return payload.StatusCode, payload.Msg
}

func assertUniformLoginLockout(t *testing.T, rec *httptest.ResponseRecorder, email string) {
	t.Helper()
	code, msg := decodeAPI(t, rec)
	if rec.Code != http.StatusTooManyRequests || code != 429 {
		t.Fatalf("lockout status/code = %d/%d body=%s", rec.Code, code, rec.Body.String())
	}
	if !strings.Contains(msg, "登录尝试过多") {
		t.Fatalf("lockout message = %q", msg)
	}
	if strings.Contains(rec.Body.String(), email) || strings.Contains(msg, "邮箱或密码错误") {
		t.Fatalf("lockout response is not generic: %s", rec.Body.String())
	}
}

func TestAccountProbeRateLimitBlocksDistinctEmails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	verifyAuth := &probeVerifyAuth{}
	verifyHandler := userauthhttp.NewUserVerifyHandler(probeVerifySettings{}, nil, verifyAuth)
	passwordHandler := userauthhttp.NewUserPasswordHandler(probePassword{})
	limit := RateLimitMiddlewareKeys(nil, RateLimitRule{
		Prefix:        "test:account_probe",
		WindowSeconds: 300,
		MaxRequests:   3,
		BlockSeconds:  300,
		MessageKey:    "error.rate_limited",
	}, KeyByIP, KeyByIPAndJSONField("email"))
	router := gin.New()
	router.POST("/api/v1/auth/send-verify-code", limit, verifyHandler.SendUserVerifyCode)
	router.POST("/api/v1/auth/forgot-password", limit, passwordHandler.UserForgotPassword)

	const ip = "203.0.113.40"
	for i, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		rec := postAccountProbe(router, ip, "/api/v1/auth/send-verify-code", fmt.Sprintf(`{"email":%q,"purpose":"telegram_bind"}`, email))
		code, msg := decodeAPI(t, rec)
		if rec.Code != http.StatusOK || code != 0 {
			t.Fatalf("probe %d status=%d code=%d msg=%s body=%s", i+1, rec.Code, code, msg, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "用户不存在") || strings.Contains(rec.Body.String(), "User not found") {
			t.Fatalf("probe leaked account existence: %s", rec.Body.String())
		}
	}
	if verifyAuth.calls != 3 {
		t.Fatalf("verify calls = %d, want 3", verifyAuth.calls)
	}

	blocked := postAccountProbe(router, ip, "/api/v1/auth/send-verify-code", `{"email":"d@example.com","purpose":"telegram_bind"}`)
	code, msg := decodeAPI(t, blocked)
	if blocked.Code != http.StatusTooManyRequests || code != 429 {
		t.Fatalf("enumeration status=%d code=%d body=%s", blocked.Code, code, blocked.Body.String())
	}
	if !strings.Contains(msg, "请求过于频繁") {
		t.Fatalf("rate limit message = %q", msg)
	}
	if verifyAuth.calls != 3 {
		t.Fatalf("blocked probe reached the handler, calls=%d", verifyAuth.calls)
	}

	shared := postAccountProbe(router, ip, "/api/v1/auth/forgot-password", `{"email":"e@example.com","code":"000000","new_password":"secret123"}`)
	if shared.Code != http.StatusTooManyRequests {
		t.Fatalf("forgot-password should share the probe limit, status=%d body=%s", shared.Code, shared.Body.String())
	}

	otherIP := postAccountProbe(router, "203.0.113.41", "/api/v1/auth/forgot-password", `{"email":"a@example.com","code":"000000","new_password":"secret123"}`)
	otherCode, otherMsg := decodeAPI(t, otherIP)
	if otherIP.Code != http.StatusOK || otherCode != 400 || otherMsg != "验证码错误" {
		t.Fatalf("other IP status=%d code=%d msg=%q body=%s", otherIP.Code, otherCode, otherMsg, otherIP.Body.String())
	}
	if strings.Contains(otherIP.Body.String(), "用户不存在") {
		t.Fatalf("forgot-password leaked account existence: %s", otherIP.Body.String())
	}
}

func TestRateLimitMiddlewareKeysCountsDuplicateKeyOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/ping", RateLimitMiddlewareKeys(nil, RateLimitRule{
		WindowSeconds: 60,
		MaxRequests:   1,
		MessageKey:    "error.rate_limited",
	}, KeyByIP, KeyByIPAndJSONField("email")), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/ping", strings.NewReader(`{}`))
	req.RemoteAddr = "198.51.100.1:10"
	req.Header.Set("Content-Type", "application/json")
	first := httptest.NewRecorder()
	router.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, duplicate IP key was counted twice: %s", first.Code, first.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/ping", strings.NewReader(`{}`))
	req.RemoteAddr = "198.51.100.1:10"
	req.Header.Set("Content-Type", "application/json")
	second := httptest.NewRecorder()
	router.ServeHTTP(second, req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", second.Code)
	}
}

type probeVerifySettings struct{}

func (probeVerifySettings) GetEmailVerificationEnabled(bool) (bool, error) { return true, nil }

func (probeVerifySettings) GetRegistrationEnabled(bool) (bool, error) { return true, nil }

type probeVerifyAuth struct {
	calls int
}

func (s *probeVerifyAuth) SendVerifyCode(context.Context, string, string, string, string) error {
	s.calls++
	return nil
}

type probePassword struct{}

func (probePassword) GetEmailVerificationEnabled(bool) (bool, error) { return true, nil }

func (probePassword) ResetPassword(string, string, string) error {
	return userauthhttp.ErrUserNotFound
}

func (probePassword) ChangePassword(uint, string, string) error { return nil }

func postAccountProbe(router http.Handler, ip, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1000"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func sameGenericLockout(a, b *httptest.ResponseRecorder) bool {
	_, msgA := mustDecodeAPI(a)
	_, msgB := mustDecodeAPI(b)
	return strings.Contains(msgA, "登录尝试过多") && strings.Contains(msgB, "登录尝试过多")
}

func mustDecodeAPI(rec *httptest.ResponseRecorder) (int, string) {
	var payload struct {
		StatusCode int    `json:"status_code"`
		Msg        string `json:"msg"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	return payload.StatusCode, payload.Msg
}
