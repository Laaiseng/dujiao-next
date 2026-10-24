package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PlusIssueRequest is the mall → plus zero-inventory issue payload.
type PlusIssueRequest struct {
	ExternalOrderNo  string `json:"external_order_no"`
	PaymentOrderNo   string `json:"payment_order_no,omitempty"`
	TradeID          string `json:"trade_id"`
	Channel          string `json:"channel"`
	ServiceType      string `json:"service_type"`
	Quantity         int    `json:"quantity"`
	ExpectedAmount   string `json:"expected_amount,omitempty"`
	ExpectedCurrency string `json:"expected_currency,omitempty"`
	Note             string `json:"note,omitempty"`
	CreditQuantity   *int   `json:"credit_quantity,omitempty"`
}

// PlusIssueResponse is the successful issue result from plus.
type PlusIssueResponse struct {
	OK              bool     `json:"ok"`
	Code            string   `json:"code"`
	Message         string   `json:"message"`
	Idempotent      bool     `json:"idempotent"`
	Cards           []string `json:"cards"`
	Issued          int      `json:"issued"`
	BepusdtVerified bool     `json:"bepusdt_verified"`
	Channel         string   `json:"channel"`
	ServiceType     string   `json:"service_type"`
}

// PlusIssuer calls plus_gift_card mall issue API.
type PlusIssuer interface {
	IssueCards(ctx context.Context, baseURL, apiToken string, req PlusIssueRequest) (*PlusIssueResponse, error)
}

type HTTPPlusIssuer struct {
	HTTP *http.Client
}

func NewHTTPPlusIssuer() *HTTPPlusIssuer {
	return &HTTPPlusIssuer{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *HTTPPlusIssuer) IssueCards(ctx context.Context, baseURL, apiToken string, req PlusIssueRequest) (*PlusIssueResponse, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	apiToken = strings.TrimSpace(apiToken)
	if baseURL == "" || apiToken == "" {
		return nil, fmt.Errorf("plus issue is not configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v2/mall/cards/issue", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiToken)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var parsed PlusIssueResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode plus issue response: %w (%s)", err, truncateRunes(string(raw), 200))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !parsed.OK {
		msg := strings.TrimSpace(parsed.Message)
		if msg == "" {
			msg = strings.TrimSpace(parsed.Code)
		}
		if msg == "" {
			msg = fmt.Sprintf("plus issue http %d", resp.StatusCode)
		}
		return &parsed, fmt.Errorf("%s", msg)
	}
	if len(parsed.Cards) == 0 {
		return &parsed, fmt.Errorf("plus issue returned no cards")
	}
	return &parsed, nil
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
