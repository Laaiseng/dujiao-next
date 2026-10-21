package netaddr

import "testing"

func TestNormalizeRiskIP(t *testing.T) {
	tests := map[string]string{
		"1.2.3.4":                   "1.2.3.4",
		"  1.2.3.4  ":               "1.2.3.4",
		"::ffff:1.2.3.4":            "1.2.3.4",
		"2001:db8:1234:5678::1":     "2001:db8:1234:5678::/64",
		"2001:db8:1234:5678::abcd":  "2001:db8:1234:5678::/64",
		"2001:db8:1234:5678::/64":   "2001:db8:1234:5678::/64",
		"2001:db8:1234:5678::1/128": "2001:db8:1234:5678::/64",
		"192.0.2.1/32":              "192.0.2.1",
		"not-an-ip":                 "",
		"2001:db8::/129":            "",
		"":                          "",
	}
	for input, expected := range tests {
		if actual := NormalizeRiskIP(input); actual != expected {
			t.Fatalf("NormalizeRiskIP(%q)=%q, want %q", input, actual, expected)
		}
	}
}
