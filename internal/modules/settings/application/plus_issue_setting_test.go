package settingsapp

import (
	"errors"
	"strings"
	"testing"

	"github.com/dujiao-next/internal/constants"
	"github.com/dujiao-next/internal/shared/jsonmap"
	"github.com/dujiao-next/internal/testkit/memorysettings"
)

func TestNormalizePlusIssueSetting(t *testing.T) {
	got := defaultSettingRegistry.Normalize(constants.SettingKeyPlusIssueConfig, jsonmap.JSON{
		"enabled":       false,
		"base_url":      " https://plus.example.com/ ",
		"api_token":     "plaintext",
		"api_token_enc": " cipher ",
		"extra":         "dropped",
	})
	if got["enabled"] != false || got["base_url"] != "https://plus.example.com" || got["api_token_enc"] != "cipher" {
		t.Fatalf("normalized = %#v", got)
	}
	if _, ok := got["api_token"]; ok {
		t.Fatalf("plaintext token must never be stored: %#v", got)
	}
	if _, ok := got["extra"]; ok {
		t.Fatalf("unexpected extra field: %#v", got)
	}
}

func TestPlusIssueTokenIsStoredEncryptedAndKeptWhenBlank(t *testing.T) {
	store := memorysettings.New()
	service := NewService(store)
	service.SetSecretKey("app-secret")

	if _, err := service.Update(constants.SettingKeyPlusIssueConfig, map[string]interface{}{
		"enabled": true, "base_url": "http://127.0.0.1:18081", "api_token": "mall-token",
	}); err != nil {
		t.Fatal(err)
	}
	stored, _ := service.GetByKey(constants.SettingKeyPlusIssueConfig)
	enc, _ := stored["api_token_enc"].(string)
	if enc == "" || strings.Contains(enc, "mall-token") {
		t.Fatalf("token must be stored encrypted, got %#v", stored)
	}
	if _, ok := stored["api_token"]; ok {
		t.Fatalf("plaintext token stored: %#v", stored)
	}

	if _, err := service.Update(constants.SettingKeyPlusIssueConfig, map[string]interface{}{
		"enabled": true, "base_url": "http://127.0.0.1:18082", "api_token": "",
	}); err != nil {
		t.Fatal(err)
	}
	runtime, err := service.GetPlusIssueRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.APIToken != "mall-token" || runtime.BaseURL != "http://127.0.0.1:18082" || !runtime.Enabled {
		t.Fatalf("runtime = %#v", runtime)
	}

	masked := MaskPlusIssueSetting(stored)
	if masked["has_api_token"] != true {
		t.Fatalf("masked = %#v", masked)
	}
	if _, ok := masked["api_token_enc"]; ok {
		t.Fatalf("ciphertext must not reach admin responses: %#v", masked)
	}
}

func TestPlusIssueLegacyPlaintextTokenIsReadAndEncryptedOnSave(t *testing.T) {
	store := memorysettings.New()
	if _, err := store.Upsert(constants.SettingKeyPlusIssueConfig, jsonmap.JSON{
		"enabled": true, "base_url": "http://127.0.0.1:18081", "api_token": "legacy-token",
	}); err != nil {
		t.Fatal(err)
	}
	service := NewService(store)
	service.SetSecretKey("app-secret")

	runtime, err := service.GetPlusIssueRuntime()
	if err != nil || runtime.APIToken != "legacy-token" {
		t.Fatalf("legacy runtime = %#v, %v", runtime, err)
	}
	if _, err := service.Update(constants.SettingKeyPlusIssueConfig, map[string]interface{}{
		"enabled": true, "base_url": "http://127.0.0.1:18081",
	}); err != nil {
		t.Fatal(err)
	}
	stored, _ := service.GetByKey(constants.SettingKeyPlusIssueConfig)
	if _, ok := stored["api_token"]; ok || stored["api_token_enc"] == "" {
		t.Fatalf("legacy token should be migrated to ciphertext: %#v", stored)
	}
	runtime, err = service.GetPlusIssueRuntime()
	if err != nil || runtime.APIToken != "legacy-token" {
		t.Fatalf("migrated runtime = %#v, %v", runtime, err)
	}
}

func TestPlusIssueTokenRequiresSecretKey(t *testing.T) {
	service := NewService(memorysettings.New())
	_, err := service.Update(constants.SettingKeyPlusIssueConfig, map[string]interface{}{
		"enabled": true, "base_url": "http://127.0.0.1:18081", "api_token": "mall-token",
	})
	if !errors.Is(err, ErrPlusIssueSecretUnavailable) {
		t.Fatalf("err = %v", err)
	}
}
