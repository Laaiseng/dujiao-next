package netaddr

import (
	"net"
	"strings"
)

// NormalizeRiskIP 生成风控键：IPv4 使用完整地址，IPv6 按 /64 前缀聚合。
// 无法解析时返回空字符串。调用方不得把空结果收成同一个全局键。
// 规则与订单风控的访客 IP 聚合一致，登录封禁复用同一实现，避免模块互相依赖。
func NormalizeRiskIP(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return formatRiskIP(ip)
	}
	// 永久封禁名单里的 IPv6 键已经是 "2001:db8:1:2::/64"。解封时要能还原同一键。
	if strings.Contains(value, "/") {
		ip, _, err := net.ParseCIDR(value)
		if err != nil || ip == nil {
			return ""
		}
		return formatRiskIP(ip)
	}
	return ""
}

func formatRiskIP(ip net.IP) string {
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}
	network := ip.Mask(net.CIDRMask(64, 128))
	if network == nil {
		return ""
	}
	return network.String() + "/64"
}
