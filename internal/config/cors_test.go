package config

import "testing"

func TestDefaultCORSAllowedOriginsAreExplicit(t *testing.T) {
	origins := DefaultCORSAllowedOrigins()
	if len(origins) == 0 {
		t.Fatal("default CORS allowlist is empty")
	}
	foundProduction := false
	for _, origin := range origins {
		if origin == "*" {
			t.Fatal("default CORS allowlist must not contain *")
		}
		if origin == "https://ai.luudan.xyz" {
			foundProduction = true
		}
	}
	if !foundProduction {
		t.Fatalf("production storefront origin missing: %v", origins)
	}
	origins[0] = "mutated"
	if DefaultCORSAllowedOrigins()[0] == "mutated" {
		t.Fatal("DefaultCORSAllowedOrigins must return a copy")
	}
}

func TestSplitCORSOrigins(t *testing.T) {
	got := splitCORSOrigins(" https://ai.luudan.xyz, http://localhost:5173 ,, \n ,http://evil.example\r\nX")
	if len(got) != 2 || got[0] != "https://ai.luudan.xyz" || got[1] != "http://localhost:5173" {
		t.Fatalf("origins = %#v", got)
	}
	if splitCORSOrigins("  ") != nil {
		t.Fatal("blank env should leave the configured allowlist untouched")
	}
}
