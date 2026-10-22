package settingssecurity

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/dujiao-next/internal/shared/jsonmap"
	"github.com/dujiao-next/internal/shared/netaddr"
)

const (
	AdminLoginBanKindIP          = "ip"
	AdminLoginBanKindFingerprint = "fingerprint"
	adminLoginFingerprintMaxLen  = 128
)

// AdminLoginBan 是后台手动添加的永久封禁主体。
type AdminLoginBan struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// AdminLoginGuardConfig 是可热更新的后台登录白名单与永久封禁。
// 失败阈值和临时封禁时长来自 config.yml，不放在这里。
type AdminLoginGuardConfig struct {
	IPWhitelist   []string        `json:"ip_whitelist"`
	PermanentBans []AdminLoginBan `json:"permanent_bans"`
}

// DefaultAdminLoginGuardConfig 默认没有任何热更新白名单或永久封禁。
func DefaultAdminLoginGuardConfig() AdminLoginGuardConfig {
	return AdminLoginGuardConfig{
		IPWhitelist:   []string{},
		PermanentBans: []AdminLoginBan{},
	}
}

// NormalizeAdminLoginGuardConfig 丢掉无法解析的 IP / 指纹，并去重。
func NormalizeAdminLoginGuardConfig(cfg AdminLoginGuardConfig) AdminLoginGuardConfig {
	cfg.IPWhitelist = normalizeIPEntries(cfg.IPWhitelist)
	cfg.PermanentBans = normalizePermanentBans(cfg.PermanentBans)
	return cfg
}

// DecodeAdminLoginGuardConfig 解析设置 JSON。
func DecodeAdminLoginGuardConfig(raw jsonmap.JSON, fallback AdminLoginGuardConfig) AdminLoginGuardConfig {
	if raw == nil {
		return NormalizeAdminLoginGuardConfig(fallback)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return NormalizeAdminLoginGuardConfig(fallback)
	}
	result := fallback
	if err := json.Unmarshal(data, &result); err != nil {
		return NormalizeAdminLoginGuardConfig(fallback)
	}
	return NormalizeAdminLoginGuardConfig(result)
}

// EncodeAdminLoginGuardConfig 序列化归一化后的配置。
func EncodeAdminLoginGuardConfig(cfg AdminLoginGuardConfig) jsonmap.JSON {
	normalized := NormalizeAdminLoginGuardConfig(cfg)
	data, err := json.Marshal(normalized)
	if err != nil {
		return jsonmap.JSON{}
	}
	var result jsonmap.JSON
	_ = json.Unmarshal(data, &result)
	return result
}

// NormalizeAdminLoginGuardConfigJSON 是 Registry 使用的原始 JSON 写入策略。
func NormalizeAdminLoginGuardConfigJSON(value jsonmap.JSON) jsonmap.JSON {
	return EncodeAdminLoginGuardConfig(DecodeAdminLoginGuardConfig(value, DefaultAdminLoginGuardConfig()))
}

// NormalizeAdminLoginFingerprint 只接受去空白后的十六进制，最长 128。
// 空值或非法值返回空字符串，调用方必须跳过指纹维度。
func NormalizeAdminLoginFingerprint(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > adminLoginFingerprintMaxLen {
		return ""
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return value
}

func normalizeIPEntries(entries []string) []string {
	clean := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" || !isValidIPOrCIDR(entry) {
			continue
		}
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		clean = append(clean, entry)
	}
	return clean
}

func normalizePermanentBans(bans []AdminLoginBan) []AdminLoginBan {
	clean := make([]AdminLoginBan, 0, len(bans))
	seen := make(map[string]struct{}, len(bans))
	for _, ban := range bans {
		kind := strings.ToLower(strings.TrimSpace(ban.Kind))
		value := strings.TrimSpace(ban.Value)
		switch kind {
		case AdminLoginBanKindIP:
			parsed := net.ParseIP(value)
			if parsed == nil {
				continue
			}
			value = netaddr.NormalizeRiskIP(parsed.String())
			if value == "" {
				continue
			}
		case AdminLoginBanKindFingerprint:
			value = NormalizeAdminLoginFingerprint(value)
			if value == "" {
				continue
			}
		default:
			continue
		}
		key := kind + "\x00" + value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		clean = append(clean, AdminLoginBan{Kind: kind, Value: value})
	}
	return clean
}
