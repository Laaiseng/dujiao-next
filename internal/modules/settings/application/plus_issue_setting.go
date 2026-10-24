package settingsapp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dujiao-next/internal/constants"
	"github.com/dujiao-next/internal/crypto"
	"github.com/dujiao-next/internal/shared/jsonmap"
)

var ErrPlusIssueSecretUnavailable = errors.New("plus issue token encryption key is not configured")

// PlusIssueRuntime is the decrypted plus_issue configuration used to call plus.
type PlusIssueRuntime struct {
	Enabled  bool
	BaseURL  string
	APIToken string
}

// SetSecretKey enables encrypting secrets stored in settings (app.secret_key).
func (s *Service) SetSecretKey(secret string) {
	if s == nil || strings.TrimSpace(secret) == "" {
		return
	}
	s.encryptKey = crypto.DeriveKey(secret)
}

// normalizePlusIssueSetting keeps only the fields the plus_issue fulfillment reads.
// The token is only ever persisted encrypted; plaintext api_token is dropped here.
func normalizePlusIssueSetting(value jsonmap.JSON) jsonmap.JSON {
	enabled := true
	if raw, ok := value["enabled"].(bool); ok {
		enabled = raw
	}
	baseURL, _ := value["base_url"].(string)
	tokenEnc, _ := value["api_token_enc"].(string)
	return jsonmap.JSON{
		"enabled":       enabled,
		"base_url":      strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		"api_token_enc": strings.TrimSpace(tokenEnc),
	}
}

// preparePlusIssueSetting encrypts a newly entered token, or keeps the stored one when the input is empty.
func (s *Service) preparePlusIssueSetting(value map[string]interface{}) (map[string]interface{}, error) {
	next := make(map[string]interface{}, len(value)+1)
	for k, v := range value {
		next[k] = v
	}
	delete(next, "api_token_enc")
	token, _ := next["api_token"].(string)
	token = strings.TrimSpace(token)
	delete(next, "api_token")

	if token != "" {
		if s.encryptKey == nil {
			return nil, ErrPlusIssueSecretUnavailable
		}
		encrypted, err := crypto.Encrypt(s.encryptKey, token)
		if err != nil {
			return nil, fmt.Errorf("encrypt plus issue token: %w", err)
		}
		next["api_token_enc"] = encrypted
		return next, nil
	}

	current, err := s.GetByKey(constants.SettingKeyPlusIssueConfig)
	if err != nil {
		return nil, err
	}
	if enc, _ := current["api_token_enc"].(string); strings.TrimSpace(enc) != "" {
		next["api_token_enc"] = enc
		return next, nil
	}
	if legacy, _ := current["api_token"].(string); strings.TrimSpace(legacy) != "" {
		if s.encryptKey == nil {
			return nil, ErrPlusIssueSecretUnavailable
		}
		encrypted, err := crypto.Encrypt(s.encryptKey, strings.TrimSpace(legacy))
		if err != nil {
			return nil, fmt.Errorf("encrypt plus issue token: %w", err)
		}
		next["api_token_enc"] = encrypted
	}
	return next, nil
}

// MaskPlusIssueSetting hides the token from admin responses, reporting only whether one is set.
func MaskPlusIssueSetting(value jsonmap.JSON) jsonmap.JSON {
	if value == nil {
		return value
	}
	enc, _ := value["api_token_enc"].(string)
	legacy, _ := value["api_token"].(string)
	masked := jsonmap.JSON{}
	for k, v := range value {
		if k == "api_token" || k == "api_token_enc" {
			continue
		}
		masked[k] = v
	}
	masked["has_api_token"] = strings.TrimSpace(enc) != "" || strings.TrimSpace(legacy) != ""
	return masked
}

// GetPlusIssueRuntime returns the decrypted config. Tokens saved before encryption are still read as plaintext.
func (s *Service) GetPlusIssueRuntime() (PlusIssueRuntime, error) {
	raw, err := s.GetByKey(constants.SettingKeyPlusIssueConfig)
	if err != nil || raw == nil {
		return PlusIssueRuntime{}, err
	}
	runtime := PlusIssueRuntime{Enabled: true}
	if v, ok := raw["enabled"].(bool); ok {
		runtime.Enabled = v
	}
	baseURL, _ := raw["base_url"].(string)
	runtime.BaseURL = strings.TrimSpace(baseURL)

	if enc, _ := raw["api_token_enc"].(string); strings.TrimSpace(enc) != "" {
		if s.encryptKey == nil {
			return PlusIssueRuntime{}, ErrPlusIssueSecretUnavailable
		}
		token, err := crypto.Decrypt(s.encryptKey, strings.TrimSpace(enc))
		if err != nil {
			return PlusIssueRuntime{}, fmt.Errorf("decrypt plus issue token: %w", err)
		}
		runtime.APIToken = strings.TrimSpace(token)
		return runtime, nil
	}
	legacy, _ := raw["api_token"].(string)
	runtime.APIToken = strings.TrimSpace(legacy)
	return runtime, nil
}
