package settingssecurity

import "testing"

func TestNormalizeAdminLoginGuardConfigDropsInvalidEntries(t *testing.T) {
	cfg := NormalizeAdminLoginGuardConfig(AdminLoginGuardConfig{
		IPWhitelist: []string{" 10.0.0.1 ", "10.0.0.1", "not-an-ip", "2001:db8::/32", ""},
		PermanentBans: []AdminLoginBan{
			{Kind: "ip", Value: "203.0.113.8"},
			{Kind: "ip", Value: "203.0.113.8"},
			{Kind: "IP", Value: "2001:db8:1:2::abcd"},
			{Kind: "fingerprint", Value: "AB12"},
			{Kind: "fingerprint", Value: "zz"},
			{Kind: "fingerprint", Value: ""},
			{Kind: "user", Value: "admin"},
		},
	})
	if len(cfg.IPWhitelist) != 2 || cfg.IPWhitelist[0] != "10.0.0.1" || cfg.IPWhitelist[1] != "2001:db8::/32" {
		t.Fatalf("whitelist = %#v", cfg.IPWhitelist)
	}
	if len(cfg.PermanentBans) != 3 {
		t.Fatalf("bans = %#v", cfg.PermanentBans)
	}
	if cfg.PermanentBans[1].Kind != AdminLoginBanKindIP || cfg.PermanentBans[1].Value != "2001:db8:1:2::/64" {
		t.Fatalf("ipv6 ban = %#v", cfg.PermanentBans[1])
	}
	if cfg.PermanentBans[2].Value != "ab12" {
		t.Fatalf("fingerprint ban = %#v", cfg.PermanentBans[2])
	}
}

func TestNormalizeAdminLoginFingerprint(t *testing.T) {
	if got := NormalizeAdminLoginFingerprint("  AbC123  "); got != "abc123" {
		t.Fatalf("got %q", got)
	}
	for _, raw := range []string{"", "   ", "abc xyz", "zzzz", "abc-123", stringsRepeat("a", 129)} {
		if got := NormalizeAdminLoginFingerprint(raw); got != "" {
			t.Fatalf("NormalizeAdminLoginFingerprint(%q)=%q, want empty", raw, got)
		}
	}
	if got := NormalizeAdminLoginFingerprint(stringsRepeat("a", 128)); got == "" {
		t.Fatal("128 hex chars must be accepted")
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
