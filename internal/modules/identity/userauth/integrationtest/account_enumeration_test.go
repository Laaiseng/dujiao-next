package integrationtest

import (
	"context"
	"errors"
	"testing"

	"github.com/dujiao-next/internal/constants"
	emailverificationdomain "github.com/dujiao-next/internal/modules/identity/emailverification/domain"
	userauthapp "github.com/dujiao-next/internal/modules/identity/userauth/application"
	"github.com/dujiao-next/internal/shared/mailbrand"
)

type recordingVerificationEmailSender struct {
	calls []string
}

func (s *recordingVerificationEmailSender) SendVerifyCode(email, _, purpose, _ string, _ mailbrand.Brand) error {
	s.calls = append(s.calls, email+"|"+purpose)
	return nil
}

func (s *recordingVerificationEmailSender) sent(email, purpose string) bool {
	want := email + "|" + purpose
	for _, call := range s.calls {
		if call == want {
			return true
		}
	}
	return false
}

func TestSendVerifyCodeDoesNotRevealMissingAccount(t *testing.T) {
	sender := &recordingVerificationEmailSender{}
	svc, _, db := newRegistrationDomainPolicyAuthServiceWithSender(t, sender)
	if _, _, _, err := svc.Register("known@example.com", "secret123", "", "", true, false); err != nil {
		t.Fatalf("register known user: %v", err)
	}

	ctx := context.Background()
	if err := svc.SendVerifyCode(ctx, "known@example.com", constants.VerifyPurposeReset, constants.LocaleZhCN, ""); err != nil {
		t.Fatalf("send reset code to known user: %v", err)
	}
	if !sender.sent("known@example.com", constants.VerifyPurposeReset) {
		t.Fatalf("known account should receive a reset code, calls=%v", sender.calls)
	}

	var issued emailverificationdomain.Code
	if err := db.Where("email = ? AND purpose = ?", "known@example.com", constants.VerifyPurposeReset).First(&issued).Error; err != nil {
		t.Fatalf("load issued reset code: %v", err)
	}
	if err := svc.ResetPassword("known@example.com", issued.Code, "secret123"); err != nil {
		t.Fatalf("legitimate reset: %v", err)
	}

	if err := svc.SendVerifyCode(ctx, "missing@example.com", constants.VerifyPurposeReset, constants.LocaleZhCN, ""); err != nil {
		t.Fatalf("missing reset account returned %v, want success", err)
	}
	if sender.sent("missing@example.com", constants.VerifyPurposeReset) {
		t.Fatalf("missing account must not be emailed, calls=%v", sender.calls)
	}
	var silent emailverificationdomain.Code
	if err := db.Where("email = ? AND purpose = ?", "missing@example.com", constants.VerifyPurposeReset).First(&silent).Error; err != nil {
		t.Fatalf("missing account should still reserve a send interval: %v", err)
	}
	if err := svc.ResetPassword("missing@example.com", silent.Code, "secret123"); !errors.Is(err, userauthapp.ErrVerifyCodeInvalid) || errors.Is(err, userauthapp.ErrNotFound) {
		t.Fatalf("reset with unsent code = %v, want invalid code", err)
	}

	unknownReset := svc.ResetPassword("never-seen@example.com", "000000", "secret123")
	knownBadCode := svc.ResetPassword("known@example.com", "000000", "secret123")
	if !errors.Is(unknownReset, userauthapp.ErrVerifyCodeInvalid) || errors.Is(unknownReset, userauthapp.ErrNotFound) {
		t.Fatalf("unknown reset = %v, want invalid code", unknownReset)
	}
	if !errors.Is(knownBadCode, userauthapp.ErrVerifyCodeInvalid) {
		t.Fatalf("known bad code = %v, want invalid code", knownBadCode)
	}

	if err := svc.SendVerifyCode(ctx, "known@example.com", constants.VerifyPurposeTelegramBind, constants.LocaleZhCN, ""); err != nil {
		t.Fatalf("send telegram bind code to known user: %v", err)
	}
	if !sender.sent("known@example.com", constants.VerifyPurposeTelegramBind) {
		t.Fatalf("known account should receive a telegram bind code, calls=%v", sender.calls)
	}
	if err := svc.SendVerifyCode(ctx, "ghost@example.com", constants.VerifyPurposeTelegramBind, constants.LocaleZhCN, ""); err != nil {
		t.Fatalf("missing telegram bind account returned %v, want success", err)
	}
	if sender.sent("ghost@example.com", constants.VerifyPurposeTelegramBind) {
		t.Fatalf("missing telegram bind account must not be emailed, calls=%v", sender.calls)
	}
	if err := svc.SendVerifyCode(ctx, "ghost@example.com", constants.VerifyPurposeTelegramBind, constants.LocaleZhCN, ""); !errors.Is(err, userauthapp.ErrVerifyCodeTooFrequent) {
		t.Fatalf("second probe of missing account = %v, want too frequent", err)
	}
	if err := svc.SendVerifyCode(ctx, "known@example.com", constants.VerifyPurposeTelegramBind, constants.LocaleZhCN, ""); !errors.Is(err, userauthapp.ErrVerifyCodeTooFrequent) {
		t.Fatalf("second probe of known account = %v, want too frequent", err)
	}
}
