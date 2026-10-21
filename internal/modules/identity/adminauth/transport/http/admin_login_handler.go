package adminauthhttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/dujiao-next/internal/app/adminloginguard"
	"github.com/dujiao-next/internal/constants"
	"github.com/dujiao-next/internal/i18n"
	"github.com/dujiao-next/internal/logger"
	captcha "github.com/dujiao-next/internal/modules/captcha/contract"
	captchahttp "github.com/dujiao-next/internal/modules/captcha/transport/http"
	ginutil "github.com/dujiao-next/internal/platform/http/ginutil"
	"github.com/dujiao-next/internal/platform/http/response"

	"github.com/gin-gonic/gin"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrWeakPassword       = errors.New("weak password")
)

// WeakPasswordError 携带可本地化的弱密码策略详情。
type WeakPasswordError struct {
	key  string
	args []interface{}
}

func NewWeakPasswordError(key string, args ...interface{}) error {
	if key == "" {
		return ErrWeakPassword
	}
	return WeakPasswordError{key: key, args: args}
}

func (e WeakPasswordError) Error() string { return e.key }

func (e WeakPasswordError) Is(target error) bool { return target == ErrWeakPassword }

func (e WeakPasswordError) Key() string { return e.key }

func (e WeakPasswordError) Args() []interface{} { return e.args }

// CaptchaVerifier 是登录端点所需的验证码端口。
type CaptchaVerifier interface {
	Verify(scene string, payload captchahttp.CaptchaPayloadRequest, clientIP string) error
}

// LoginAuthService 是管理员登录与改密端口。
type LoginAuthService interface {
	Login(username, password string) (*AuthLoginResult, error)
	ChangePassword(adminID uint, oldPassword, newPassword string) error
}

// LoginAttemptGuard 统计后台登录失败并在成功后清计数。白名单与已封禁由中间件处理。
type LoginAttemptGuard interface {
	RecordFailure(ctx context.Context, rawIP, fingerprint string) (adminloginguard.Failure, error)
	ClearFailures(ctx context.Context, rawIP, fingerprint string) error
}

// AdminLoginHandler 处理管理员登录与改密 HTTP 请求。
type AdminLoginHandler struct {
	auth     LoginAuthService
	captcha  CaptchaVerifier
	recorder AdminLoginRecorder
	guard    LoginAttemptGuard
}

func NewAdminLoginHandler(auth LoginAuthService, captcha CaptchaVerifier, recorder AdminLoginRecorder, guard LoginAttemptGuard) *AdminLoginHandler {
	if auth == nil {
		panic("admin login handler: auth is nil")
	}
	return &AdminLoginHandler{auth: auth, captcha: captcha, recorder: recorder, guard: guard}
}

func (h *AdminLoginHandler) writeLoginLog(c *gin.Context, adminID uint, username, eventType, status, failReason string, operatorID *uint) {
	if h == nil || h.recorder == nil || c == nil {
		return
	}
	requestID := ""
	if rid, ok := c.Get("request_id"); ok {
		if value, ok := rid.(string); ok {
			requestID = value
		}
	}
	h.recorder.Record(adminID, username, eventType, status, failReason, c.ClientIP(), c.Request.UserAgent(), requestID, operatorID, adminloginguard.ObservedFingerprint(c), contextInt(c, adminLoginAuditIPFailKey), contextInt(c, adminLoginAuditFPFailKey))
}

// LoginRequest 登录请求。
type LoginRequest struct {
	Username       string                            `json:"username" binding:"required"`
	Password       string                            `json:"password" binding:"required"`
	CaptchaPayload captchahttp.CaptchaPayloadRequest `json:"captcha_payload"`
}

// AdminLogin 管理员登录。
func (h *AdminLoginHandler) AdminLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ginutil.RespondBindError(c, err)
		return
	}

	if h.captcha != nil {
		if captchaErr := h.captcha.Verify(constants.CaptchaSceneLogin, req.CaptchaPayload, c.ClientIP()); captchaErr != nil {
			switch {
			case errors.Is(captchaErr, captcha.ErrRequired):
				ginutil.RespondError(c, response.CodeBadRequest, "error.captcha_required", nil)
				return
			case errors.Is(captchaErr, captcha.ErrInvalid):
				ginutil.RespondError(c, response.CodeBadRequest, "error.captcha_invalid", nil)
				return
			case errors.Is(captchaErr, captcha.ErrConfigInvalid):
				ginutil.RespondError(c, response.CodeInternal, "error.captcha_config_invalid", captchaErr)
				return
			default:
				ginutil.RespondError(c, response.CodeInternal, "error.captcha_verify_failed", captchaErr)
				return
			}
		}
	}

	loginRes, err := h.auth.Login(req.Username, req.Password)
	if err != nil {
		failReason := constants.AdminLoginFailInvalidCredentials
		if !errors.Is(err, ErrInvalidCredentials) {
			failReason = constants.AdminLoginFailInternal
		}
		if errors.Is(err, ErrInvalidCredentials) {
			result := applyLoginFailure(c, h.guard)
			failReason = constants.AdminLoginFailPasswordWrong
			if result.Banned {
				failReason = constants.AdminLoginFailAutoBanned
			}
			h.writeLoginLog(c, 0, req.Username, constants.AdminLoginEventLoginPassword, constants.AdminLoginStatusFailed, failReason, nil)
			if result.Banned {
				respondAdminLoginBanned(c, result)
				return
			}
			ginutil.RespondError(c, response.CodeUnauthorized, "error.admin_login_invalid", nil)
			return
		}
		h.writeLoginLog(c, 0, req.Username, constants.AdminLoginEventLoginPassword, constants.AdminLoginStatusFailed, failReason, nil)
		ginutil.RespondError(c, response.CodeInternal, "error.login_failed", err)
		return
	}

	applyLoginSuccess(c, h.guard)
	if loginRes.RequiresTOTP {
		h.writeLoginLog(c, loginRes.Admin.ID, loginRes.Admin.Username, constants.AdminLoginEventLoginPassword, constants.AdminLoginStatusSuccess, "", nil)
		response.Success(c, gin.H{
			"requires_totp":        true,
			"challenge_token":      loginRes.ChallengeToken,
			"challenge_expires_at": loginRes.ChallengeExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		})
		return
	}

	h.writeLoginLog(c, loginRes.Admin.ID, loginRes.Admin.Username, constants.AdminLoginEventLoginPassword, constants.AdminLoginStatusSuccess, "", nil)
	response.Success(c, gin.H{
		"requires_totp": false,
		"token":         loginRes.Token,
		"user": gin.H{
			"id":       loginRes.Admin.ID,
			"username": loginRes.Admin.Username,
		},
		"expires_at": loginRes.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// UpdatePasswordRequest 修改密码请求。
type UpdatePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// UpdateAdminPassword 修改管理员密码。
func (h *AdminLoginHandler) UpdateAdminPassword(c *gin.Context) {
	id, ok := ginutil.GetAdminID(c)
	if !ok {
		return
	}

	var req UpdatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ginutil.RespondBindError(c, err)
		return
	}

	if err := h.auth.ChangePassword(id, req.OldPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, ErrInvalidPassword):
			ginutil.RespondError(c, response.CodeBadRequest, "error.password_old_invalid", nil)
		case errors.Is(err, ErrWeakPassword):
			respondWeakPassword(c, err)
		case errors.Is(err, ErrNotFound):
			ginutil.RespondError(c, response.CodeNotFound, "error.user_not_found", nil)
		default:
			ginutil.RespondError(c, response.CodeInternal, "error.save_failed", err)
		}
		return
	}

	response.Success(c, nil)
}

const (
	adminLoginAuditIPFailKey = "admin_login_audit_ip_fail"
	adminLoginAuditFPFailKey = "admin_login_audit_fp_fail"
)

func applyLoginFailure(c *gin.Context, guard LoginAttemptGuard) adminloginguard.Failure {
	if guard == nil || c == nil || c.Request == nil || adminloginguard.WhitelistedFromContext(c) {
		return adminloginguard.Failure{}
	}
	result, err := guard.RecordFailure(c.Request.Context(), c.ClientIP(), adminloginguard.ObservedFingerprint(c))
	if err != nil {
		logger.Warnw("admin_login_guard_record_failed", "error", err)
		return adminloginguard.Failure{}
	}
	c.Set(adminLoginAuditIPFailKey, result.IPFails)
	c.Set(adminLoginAuditFPFailKey, result.FPFails)
	return result
}

func applyLoginSuccess(c *gin.Context, guard LoginAttemptGuard) {
	if guard == nil || c == nil || c.Request == nil {
		return
	}
	if err := guard.ClearFailures(c.Request.Context(), c.ClientIP(), adminloginguard.ObservedFingerprint(c)); err != nil {
		logger.Warnw("admin_login_guard_clear_failed", "error", err)
	}
}

func respondAdminLoginBanned(c *gin.Context, result adminloginguard.Failure) {
	locale := i18n.ResolveLocale(c)
	if result.Permanent {
		response.ErrorWithHTTPStatus(c, http.StatusTooManyRequests, response.CodeTooManyRequests, i18n.T(locale, "error.admin_login_banned_permanent"))
		return
	}
	wait := result.RetryAfterSeconds
	if wait < 1 {
		wait = 1
	}
	response.ErrorWithHTTPStatus(c, http.StatusTooManyRequests, response.CodeTooManyRequests, i18n.Sprintf(locale, "error.admin_login_banned", wait))
}

func contextInt(c *gin.Context, key string) int {
	if c == nil {
		return 0
	}
	value, ok := c.Get(key)
	if !ok {
		return 0
	}
	switch n := value.(type) {
	case int:
		return n
	case int64:
		return int(n)
	default:
		return 0
	}
}

func respondWeakPassword(c *gin.Context, err error) {
	locale := i18n.ResolveLocale(c)
	if perr, ok := err.(interface {
		Key() string
		Args() []interface{}
	}); ok {
		msg := i18n.Sprintf(locale, perr.Key(), perr.Args()...)
		ginutil.RespondErrorWithMsg(c, response.CodeBadRequest, msg, nil)
		return
	}
	ginutil.RespondError(c, response.CodeBadRequest, "error.password_weak", nil)
}
