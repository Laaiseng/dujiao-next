package adminloginguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/dujiao-next/internal/i18n"
	settingssecurity "github.com/dujiao-next/internal/modules/settings/schema/security"
	"github.com/dujiao-next/internal/platform/http/response"

	"github.com/gin-gonic/gin"
)

// AuditFunc 记录「已经封禁、不再累计」的审计。调用方负责落库。
type AuditFunc func(*gin.Context, Decision)

// Protect 在限流和密码校验之前拒绝已封禁请求。
// 白名单跳过失败封禁，也不进入后面的登录限流。
// rateLimit 为 nil 时，未封禁请求直接进入处理函数。
func Protect(guard *Guard, rateLimit gin.HandlerFunc, audit AuditFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if guard == nil {
			if rateLimit != nil {
				rateLimit(c)
				return
			}
			c.Next()
			return
		}
		rawFingerprint := ""
		if c.Request != nil {
			rawFingerprint = c.GetHeader(HeaderFingerprint)
		}
		decision, _ := guard.Inspect(requestContext(c), c.ClientIP(), rawFingerprint)
		c.Set(ContextFingerprintKey, decision.Subject.Fingerprint)
		c.Set(ContextWhitelistedKey, decision.Whitelisted)
		if decision.Banned {
			if audit != nil && guard.AllowAudit(requestContext(c), decision.Subject) {
				decision.Username = readUsername(c)
				audit(c, decision)
			}
			rejectBanned(c, decision)
			return
		}
		if decision.Whitelisted || rateLimit == nil {
			c.Next()
			return
		}
		rateLimit(c)
	}
}

// ObservedFingerprint 返回中间件清洗后的指纹；中间件未运行时自行清洗请求头。
func ObservedFingerprint(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if value, ok := c.Get(ContextFingerprintKey); ok {
		if fingerprint, ok := value.(string); ok {
			return fingerprint
		}
	}
	if c.Request == nil {
		return ""
	}
	return settingssecurity.NormalizeAdminLoginFingerprint(c.GetHeader(HeaderFingerprint))
}

// WhitelistedFromContext 报告本次请求是否命中登录白名单。
func WhitelistedFromContext(c *gin.Context) bool {
	if c == nil {
		return false
	}
	value, ok := c.Get(ContextWhitelistedKey)
	if !ok {
		return false
	}
	flagged, _ := value.(bool)
	return flagged
}

func requestContext(c *gin.Context) context.Context {
	if c == nil || c.Request == nil {
		return context.Background()
	}
	return c.Request.Context()
}

func rejectBanned(c *gin.Context, decision Decision) {
	locale := i18n.ResolveLocale(c)
	if decision.Permanent {
		response.ErrorWithHTTPStatus(c, http.StatusTooManyRequests, response.CodeTooManyRequests, i18n.T(locale, "error.admin_login_banned_permanent"))
		return
	}
	wait := decision.RetryAfterSeconds
	if wait < 1 {
		wait = 1
	}
	c.Header("Retry-After", strconv.Itoa(wait))
	response.ErrorWithHTTPStatus(c, http.StatusTooManyRequests, response.CodeTooManyRequests, i18n.Sprintf(locale, "error.admin_login_banned", wait))
}

func readUsername(c *gin.Context) string {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<16))
	if err != nil || len(body) == 0 {
		return ""
	}
	var payload struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	username := strings.TrimSpace(payload.Username)
	if len(username) > 128 {
		username = username[:128]
	}
	return username
}
