package userauthhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dujiao-next/internal/platform/http/response"

	"github.com/gin-gonic/gin"
)

func TestRespondTelegramBindError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name string
		err  error
		code int
		msg  string
	}{
		{
			name: "auth disabled",
			err:  ErrTelegramAuthDisabled,
			code: response.CodeBadRequest,
			msg:  "Telegram 登录未启用",
		},
		{
			name: "identity conflict",
			err:  ErrUserOAuthIdentityExists,
			code: response.CodeBadRequest,
			msg:  "该 Telegram 账号已绑定其他用户",
		},
		{
			name: "unknown error",
			err:  errors.New("boom"),
			code: response.CodeInternal,
			msg:  "更新用户资料失败",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder := newTelegramErrorTestContext()
			respondTelegramBindError(c, tt.err)
			assertTelegramErrorResponse(t, recorder, tt.code, tt.msg)
		})
	}
}

func TestRespondTelegramLoginError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name string
		err  error
		code int
		msg  string
	}{
		{
			name: "expired auth payload",
			err:  ErrTelegramAuthExpired,
			code: response.CodeBadRequest,
			msg:  "Telegram 登录已过期，请重试",
		},
		{
			name: "disabled user",
			err:  ErrUserDisabled,
			code: response.CodeUnauthorized,
			msg:  "账号已禁用",
		},
		{
			name: "registration disabled",
			err:  ErrRegistrationDisabled,
			code: response.CodeForbidden,
			msg:  "注册功能已关闭",
		},
		{
			name: "unknown error",
			err:  errors.New("boom"),
			code: response.CodeInternal,
			msg:  "登录失败",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder := newTelegramErrorTestContext()
			h := &UserTelegramHandler{}
			h.respondTelegramLoginError(c, tt.err)
			assertTelegramErrorResponse(t, recorder, tt.code, tt.msg)
		})
	}
}

func newTelegramErrorTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	return c, recorder
}

func TestPublicVerifyCodeDoesNotRevealWhetherAccountExists(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, purpose := range []string{"telegram_bind", "reset", "Telegram_Bind"} {
		t.Run(purpose, func(t *testing.T) {
			missingAuth := &scriptedVerifyAuth{err: ErrUserNotFound}
			existingAuth := &scriptedVerifyAuth{}
			missing := postVerifyCode(t, missingAuth, purpose, "")
			existing := postVerifyCode(t, existingAuth, purpose, "")
			if missing.Code != http.StatusOK || existing.Code != http.StatusOK {
				t.Fatalf("http status missing=%d existing=%d", missing.Code, existing.Code)
			}
			if missing.Body.String() != existing.Body.String() {
				t.Fatalf("responses diverged\nmissing=%s\nexisting=%s", missing.Body.String(), existing.Body.String())
			}
			if strings.Contains(missing.Body.String(), "用户不存在") || strings.Contains(missing.Body.String(), "User not found") {
				t.Fatalf("response leaked account existence: %s", missing.Body.String())
			}
			code, msg := decodePublicAuth(t, missing)
			if code != 0 || msg != "若账号存在，验证码将发送到该邮箱" {
				t.Fatalf("status_code=%d msg=%q body=%s", code, msg, missing.Body.String())
			}
			if !strings.Contains(missing.Body.String(), `"sent":true`) {
				t.Fatalf("expected sent=true, body=%s", missing.Body.String())
			}
		})
	}

	t.Run("english", func(t *testing.T) {
		missing := postVerifyCode(t, &scriptedVerifyAuth{err: ErrUserNotFound}, "telegram_bind", "en-US")
		existing := postVerifyCode(t, &scriptedVerifyAuth{}, "telegram_bind", "en-US")
		if missing.Body.String() != existing.Body.String() {
			t.Fatalf("responses diverged\nmissing=%s\nexisting=%s", missing.Body.String(), existing.Body.String())
		}
		_, msg := decodePublicAuth(t, missing)
		if msg != "If the account exists, a verification code will be sent to that email" {
			t.Fatalf("msg=%q body=%s", msg, missing.Body.String())
		}
	})
}

func TestPublicForgotPasswordDoesNotRevealWhetherAccountExists(t *testing.T) {
	gin.SetMode(gin.TestMode)

	missing := postForgotPassword(t, scriptedPassword{err: ErrUserNotFound})
	invalid := postForgotPassword(t, scriptedPassword{err: ErrVerifyCodeInvalid})
	if missing.Code != http.StatusOK || invalid.Code != http.StatusOK {
		t.Fatalf("http status missing=%d invalid=%d", missing.Code, invalid.Code)
	}
	if missing.Body.String() != invalid.Body.String() {
		t.Fatalf("responses diverged\nmissing=%s\ninvalid=%s", missing.Body.String(), invalid.Body.String())
	}
	code, msg := decodePublicAuth(t, missing)
	if code != response.CodeBadRequest || msg != "验证码错误" {
		t.Fatalf("status_code=%d msg=%q body=%s", code, msg, missing.Body.String())
	}
	if strings.Contains(missing.Body.String(), "用户不存在") || strings.Contains(missing.Body.String(), "User not found") {
		t.Fatalf("response leaked account existence: %s", missing.Body.String())
	}

	reset := postForgotPassword(t, scriptedPassword{})
	okCode, okMsg := decodePublicAuth(t, reset)
	if reset.Code != http.StatusOK || okCode != 0 || okMsg != "success" || !strings.Contains(reset.Body.String(), `"reset":true`) {
		t.Fatalf("legitimate reset changed: %s", reset.Body.String())
	}
}

func TestRegisterVerifyCodeStillReportsExistingEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := postVerifyCode(t, &scriptedVerifyAuth{err: ErrEmailExists}, "register", "")
	code, msg := decodePublicAuth(t, rec)
	if code != response.CodeBadRequest || msg != "邮箱已注册" {
		t.Fatalf("status_code=%d msg=%q body=%s", code, msg, rec.Body.String())
	}
}

type scriptedVerifyAuth struct {
	err   error
	calls int
}

func (s *scriptedVerifyAuth) SendVerifyCode(context.Context, string, string, string, string) error {
	s.calls++
	return s.err
}

type verifySettingsStub struct{}

func (verifySettingsStub) GetEmailVerificationEnabled(bool) (bool, error) { return true, nil }

func (verifySettingsStub) GetRegistrationEnabled(bool) (bool, error) { return true, nil }

type scriptedPassword struct {
	err error
}

func (scriptedPassword) GetEmailVerificationEnabled(bool) (bool, error) { return true, nil }

func (s scriptedPassword) ResetPassword(string, string, string) error { return s.err }

func (scriptedPassword) ChangePassword(uint, string, string) error { return nil }

func postVerifyCode(t *testing.T, auth *scriptedVerifyAuth, purpose, lang string) *httptest.ResponseRecorder {
	t.Helper()
	handler := NewUserVerifyHandler(verifySettingsStub{}, nil, auth)
	router := gin.New()
	router.POST("/api/v1/auth/send-verify-code", handler.SendUserVerifyCode)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/send-verify-code", strings.NewReader(fmt.Sprintf(`{"email":"person@example.com","purpose":%q}`, purpose)))
	req.Header.Set("Content-Type", "application/json")
	if lang != "" {
		req.Header.Set("X-Lang", lang)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if auth.calls != 1 {
		t.Fatalf("SendVerifyCode calls = %d, want 1", auth.calls)
	}
	return rec
}

func postForgotPassword(t *testing.T, service scriptedPassword) *httptest.ResponseRecorder {
	t.Helper()
	handler := NewUserPasswordHandler(service)
	router := gin.New()
	router.POST("/api/v1/auth/forgot-password", handler.UserForgotPassword)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", strings.NewReader(`{"email":"person@example.com","code":"000000","new_password":"secret123"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodePublicAuth(t *testing.T, rec *httptest.ResponseRecorder) (int, string) {
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

func assertTelegramErrorResponse(t *testing.T, recorder *httptest.ResponseRecorder, wantCode int, wantMsg string) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var body response.Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.StatusCode != wantCode {
		t.Fatalf("status_code = %d, want %d; body=%s", body.StatusCode, wantCode, recorder.Body.String())
	}
	if body.Msg != wantMsg {
		t.Fatalf("msg = %q, want %q; body=%s", body.Msg, wantMsg, recorder.Body.String())
	}
}
