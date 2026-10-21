package auditloghttp

import (
	"errors"
	"strings"

	"github.com/dujiao-next/internal/app/adminloginguard"
	"github.com/dujiao-next/internal/modules/auditlog/contract"
	"github.com/dujiao-next/internal/platform/http/ginutil"
	"github.com/dujiao-next/internal/platform/http/response"

	"github.com/gin-gonic/gin"
)

// GetUserLoginLogs 获取用户登录日志列表
func (h *AdminHandler) GetUserLoginLogs(c *gin.Context) {
	page, pageSize := ginutil.ParsePagination(c)

	userIDRaw := c.Query("user_id")
	email := strings.TrimSpace(c.Query("email"))
	status := strings.TrimSpace(c.Query("status"))
	failReason := strings.TrimSpace(c.Query("fail_reason"))
	clientIP := strings.TrimSpace(c.Query("client_ip"))

	var userID uint
	if userIDRaw != "" {
		parsedUserID, err := ginutil.ParseQueryUint(userIDRaw, false)
		if err != nil {
			ginutil.RespondError(c, response.CodeBadRequest, "error.bad_request", err)
			return
		}
		userID = parsedUserID
	}

	createdFrom, createdTo, err := ginutil.ParseQueryTimeRange(c, "created_from", "created_to")
	if err != nil {
		ginutil.RespondError(c, response.CodeBadRequest, "error.bad_request", err)
		return
	}

	logs, total, err := h.userLoginLogs.ListForAdmin(contract.UserLoginFilter{
		Page:        page,
		PageSize:    pageSize,
		UserID:      userID,
		Email:       email,
		Status:      status,
		FailReason:  failReason,
		ClientIP:    clientIP,
		CreatedFrom: createdFrom,
		CreatedTo:   createdTo,
	})
	if err != nil {
		ginutil.RespondError(c, response.CodeInternal, "error.user_login_log_fetch_failed", err)
		return
	}

	pagination := response.BuildPagination(page, pageSize, total)
	response.SuccessWithPage(c, logs, pagination)
}

// GetAdminLoginLogs 获取后台登录与封禁审计。
func (h *AdminHandler) GetAdminLoginLogs(c *gin.Context) {
	if h == nil || h.adminLoginLogs == nil {
		ginutil.RespondError(c, response.CodeInternal, "error.admin_login_log_fetch_failed", nil)
		return
	}
	page, pageSize := ginutil.ParsePagination(c)
	createdFrom, createdTo, err := ginutil.ParseQueryTimeRange(c, "created_from", "created_to")
	if err != nil {
		ginutil.RespondError(c, response.CodeBadRequest, "error.bad_request", err)
		return
	}
	var adminID *uint
	if raw := strings.TrimSpace(c.Query("admin_id")); raw != "" {
		parsed, parseErr := ginutil.ParseQueryUint(raw, false)
		if parseErr != nil {
			ginutil.RespondError(c, response.CodeBadRequest, "error.bad_request", parseErr)
			return
		}
		adminID = &parsed
	}
	logs, total, err := h.adminLoginLogs.List(contract.AdminLoginFilter{
		Page:        page,
		PageSize:    pageSize,
		AdminID:     adminID,
		Username:    strings.TrimSpace(c.Query("username")),
		EventType:   strings.TrimSpace(c.Query("event_type")),
		Status:      strings.TrimSpace(c.Query("status")),
		FailReason:  strings.TrimSpace(c.Query("fail_reason")),
		ClientIP:    strings.TrimSpace(c.Query("client_ip")),
		Fingerprint: strings.TrimSpace(c.Query("fingerprint")),
		CreatedFrom: createdFrom,
		CreatedTo:   createdTo,
	})
	if err != nil {
		ginutil.RespondError(c, response.CodeInternal, "error.admin_login_log_fetch_failed", err)
		return
	}
	response.SuccessWithPage(c, logs, response.BuildPagination(page, pageSize, total))
}

type adminLoginBanRequest struct {
	ClientIP    string `json:"client_ip"`
	Fingerprint string `json:"fingerprint"`
}

// UnbanAdminLogin 删除临时封禁、失败计数和匹配的永久封禁。
func (h *AdminHandler) UnbanAdminLogin(c *gin.Context) {
	h.changeAdminLoginBan(c, false)
}

// BanAdminLogin 手动永久封禁 IP 和 / 或指纹。自动封禁不会调用这里。
func (h *AdminHandler) BanAdminLogin(c *gin.Context) {
	h.changeAdminLoginBan(c, true)
}

func (h *AdminHandler) changeAdminLoginBan(c *gin.Context, permanent bool) {
	if h == nil || h.loginBans == nil {
		ginutil.RespondError(c, response.CodeInternal, "error.save_failed", nil)
		return
	}
	var req adminLoginBanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ginutil.RespondBindError(c, err)
		return
	}
	var err error
	if permanent {
		err = h.loginBans.BanPermanent(c.Request.Context(), req.ClientIP, req.Fingerprint)
	} else {
		err = h.loginBans.Unban(c.Request.Context(), req.ClientIP, req.Fingerprint)
	}
	if err != nil {
		if errors.Is(err, adminloginguard.ErrEmptySubject) {
			ginutil.RespondError(c, response.CodeBadRequest, "error.admin_login_ban_target_invalid", nil)
			return
		}
		ginutil.RespondError(c, response.CodeInternal, "error.save_failed", err)
		return
	}
	response.Success(c, nil)
}
