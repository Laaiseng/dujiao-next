package adminloginguard

import (
	"context"
	"sync"
	"testing"
	"time"

	settingssecurity "github.com/dujiao-next/internal/modules/settings/schema/security"
)

func newTestGuard(maxFailures int, whitelist ...string) *Guard {
	return New(Options{
		MaxFailures:     maxFailures,
		Window:          15 * time.Minute,
		BanFor:          time.Hour,
		StaticWhitelist: whitelist,
		PolicyTTL:       -1,
		Prefix:          "dj",
	})
}

func TestRecordFailureBansAtThreshold(t *testing.T) {
	guard := newTestGuard(2)
	ctx := context.Background()
	first, err := guard.RecordFailure(ctx, "203.0.113.10", "")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if first.Banned || first.IPFails != 1 {
		t.Fatalf("first failure = %+v", first)
	}
	second, err := guard.RecordFailure(ctx, "203.0.113.10", "aa")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if !second.Banned || second.IPFails != 2 || second.Dimension != kindIP {
		t.Fatalf("second failure = %+v", second)
	}
	decision, err := guard.Inspect(ctx, "203.0.113.10", "")
	if err != nil || !decision.Banned || decision.Permanent {
		t.Fatalf("inspect = %+v err=%v", decision, err)
	}
}

func TestAlreadyBannedDoesNotIncrement(t *testing.T) {
	guard := newTestGuard(2)
	ctx := context.Background()
	if _, err := guard.RecordFailure(ctx, "203.0.113.11", "ab"); err != nil {
		t.Fatal(err)
	}
	banned, err := guard.RecordFailure(ctx, "203.0.113.11", "ab")
	if err != nil || !banned.Banned {
		t.Fatalf("expected ban, got %+v err=%v", banned, err)
	}
	again, err := guard.RecordFailure(ctx, "203.0.113.11", "ab")
	if err != nil {
		t.Fatal(err)
	}
	if !again.Banned || again.IPFails != 2 || again.FPFails != 2 {
		t.Fatalf("banned request changed counters: %+v", again)
	}
	if got := guard.local.peek(guard.failKey(kindIP, "203.0.113.11"), guard.now()); got != 2 {
		t.Fatalf("ip counter = %d, want 2", got)
	}
	if got := guard.local.peek(guard.failKey(kindFP, "ab"), guard.now()); got != 2 {
		t.Fatalf("fp counter = %d, want 2", got)
	}
}

func TestWhitelistSkipsCountAndBan(t *testing.T) {
	guard := newTestGuard(2, "10.0.0.0/8")
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		failure, err := guard.RecordFailure(ctx, "10.1.2.3", "cd")
		if err != nil {
			t.Fatal(err)
		}
		if failure.Banned || failure.IPFails != 0 || failure.FPFails != 0 {
			t.Fatalf("whitelisted failure counted: %+v", failure)
		}
	}
	decision, err := guard.Inspect(ctx, "10.1.2.3", "cd")
	if err != nil || !decision.Whitelisted || decision.Banned {
		t.Fatalf("inspect = %+v err=%v", decision, err)
	}
	if guard.local.peek(guard.failKey(kindFP, "cd"), guard.now()) != 0 {
		t.Fatal("fingerprint of a whitelisted IP was counted")
	}
}

func TestHotWhitelistIsUnioned(t *testing.T) {
	guard := newTestGuard(1)
	policy := &memPolicy{policy: Policy{IPWhitelist: []string{"192.0.2.20"}}}
	guard.policies = policy
	failure, err := guard.RecordFailure(context.Background(), "192.0.2.20", "")
	if err != nil || failure.Banned || failure.IPFails != 0 {
		t.Fatalf("hot whitelist failure = %+v err=%v", failure, err)
	}
}

func TestSuccessClearsFailuresButNotBan(t *testing.T) {
	guard := newTestGuard(2)
	ctx := context.Background()
	if _, err := guard.RecordFailure(ctx, "203.0.113.20", "ee"); err != nil {
		t.Fatal(err)
	}
	if err := guard.ClearFailures(ctx, "203.0.113.20", "ee"); err != nil {
		t.Fatal(err)
	}
	decision, err := guard.Inspect(ctx, "203.0.113.20", "ee")
	if err != nil || decision.Banned || decision.IPFails != 0 || decision.FPFails != 0 {
		t.Fatalf("cleared inspect = %+v err=%v", decision, err)
	}

	if _, err := guard.RecordFailure(ctx, "203.0.113.21", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RecordFailure(ctx, "203.0.113.21", ""); err != nil {
		t.Fatal(err)
	}
	if err := guard.ClearFailures(ctx, "203.0.113.21", ""); err != nil {
		t.Fatal(err)
	}
	decision, err = guard.Inspect(ctx, "203.0.113.21", "")
	if err != nil || !decision.Banned || decision.IPFails != 0 {
		t.Fatalf("ban must survive success clear: %+v err=%v", decision, err)
	}
}

func TestInvalidFingerprintIsSkipped(t *testing.T) {
	guard := newTestGuard(5)
	ctx := context.Background()
	for _, fingerprint := range []string{"", "   ", "not hex", "zzzz", "abc-12"} {
		if _, err := guard.RecordFailure(ctx, "198.51.100.8", fingerprint); err != nil {
			t.Fatal(err)
		}
	}
	decision, err := guard.Inspect(ctx, "198.51.100.8", "zzzz")
	if err != nil {
		t.Fatal(err)
	}
	if decision.IPFails != 5 || decision.FPFails != 0 || decision.Subject.Fingerprint != "" {
		t.Fatalf("invalid fingerprints collapsed or counted: %+v", decision)
	}
	for key := range guard.local.entries {
		if len(key) >= len(guard.prefix+":loginfail:v1:admin:fp:") && key[:len(guard.prefix+":loginfail:v1:admin:fp:")] == guard.prefix+":loginfail:v1:admin:fp:" {
			t.Fatalf("unexpected fingerprint key %s", key)
		}
	}
	valid, err := guard.RecordFailure(ctx, "198.51.100.9", "AbC")
	if err != nil || valid.FPFails != 1 || valid.Fingerprint != "abc" {
		t.Fatalf("valid fingerprint = %+v err=%v", valid, err)
	}
	if decision, _ = guard.Inspect(ctx, "198.51.100.8", "abc"); decision.FPFails != 1 || decision.IPFails != 5 {
		t.Fatalf("fingerprint leaked across invalid values: %+v", decision)
	}
}

func TestFingerprintBanIsIndependentOfIP(t *testing.T) {
	guard := newTestGuard(2)
	ctx := context.Background()
	if _, err := guard.RecordFailure(ctx, "203.0.113.30", "ff"); err != nil {
		t.Fatal(err)
	}
	banned, err := guard.RecordFailure(ctx, "203.0.113.31", "ff")
	if err != nil || !banned.Banned || banned.Dimension != kindFP || banned.FPFails != 2 {
		t.Fatalf("fingerprint ban = %+v err=%v", banned, err)
	}
	decision, err := guard.Inspect(ctx, "203.0.113.32", "ff")
	if err != nil || !decision.Banned || decision.Dimension != kindFP {
		t.Fatalf("new ip same fingerprint = %+v err=%v", decision, err)
	}
	other, err := guard.RecordFailure(ctx, "203.0.113.32", "f0")
	if err != nil || other.Banned || other.IPFails != 1 {
		t.Fatalf("different fingerprint should stay open: %+v err=%v", other, err)
	}
	again, err := guard.RecordFailure(ctx, "203.0.113.33", "ff")
	if err != nil || !again.Banned || again.FPFails != 2 {
		t.Fatalf("already banned fingerprint incremented: %+v err=%v", again, err)
	}
}

func TestIPv6FailuresAggregateToPrefix(t *testing.T) {
	guard := newTestGuard(2)
	ctx := context.Background()
	if _, err := guard.RecordFailure(ctx, "2001:db8:1:2::1", ""); err != nil {
		t.Fatal(err)
	}
	failure, err := guard.RecordFailure(ctx, "2001:db8:1:2::abcd", "")
	if err != nil || !failure.Banned || failure.IPFails != 2 {
		t.Fatalf("same /64 = %+v err=%v", failure, err)
	}
	other, err := guard.RecordFailure(ctx, "2001:db8:1:3::1", "")
	if err != nil || other.Banned || other.IPFails != 1 {
		t.Fatalf("other /64 = %+v err=%v", other, err)
	}
}

func TestPermanentBanAndUnban(t *testing.T) {
	guard := newTestGuard(5)
	policy := &memPolicy{}
	guard.policies = policy
	ctx := context.Background()
	if err := guard.BanPermanent(ctx, "203.0.113.40", "abcd"); err != nil {
		t.Fatal(err)
	}
	decision, err := guard.Inspect(ctx, "203.0.113.40", "")
	if err != nil || !decision.Banned || !decision.Permanent || decision.Dimension != kindIP {
		t.Fatalf("permanent ip = %+v err=%v", decision, err)
	}
	failure, err := guard.RecordFailure(ctx, "203.0.113.40", "")
	if err != nil || !failure.Banned || failure.IPFails != 0 {
		t.Fatalf("permanent ban incremented: %+v err=%v", failure, err)
	}
	fingerprint, err := guard.Inspect(ctx, "198.51.100.1", "ABCD")
	if err != nil || !fingerprint.Banned || !fingerprint.Permanent || fingerprint.Dimension != kindFP {
		t.Fatalf("permanent fingerprint = %+v err=%v", fingerprint, err)
	}
	if err := guard.Unban(ctx, "203.0.113.40", "abcd"); err != nil {
		t.Fatal(err)
	}
	decision, err = guard.Inspect(ctx, "203.0.113.40", "abcd")
	if err != nil || decision.Banned {
		t.Fatalf("unban left a ban: %+v err=%v", decision, err)
	}
	if len(policy.policy.PermanentBans) != 0 {
		t.Fatalf("permanent bans remain: %#v", policy.policy.PermanentBans)
	}
	if err := guard.BanPermanent(ctx, "2001:db8:9:8::1", ""); err != nil {
		t.Fatal(err)
	}
	stored := policy.policy.PermanentBans
	if len(stored) != 1 || stored[0].Value != "2001:db8:9:8::/64" {
		t.Fatalf("ipv6 permanent = %#v", stored)
	}
	if err := guard.Unban(ctx, stored[0].Value, ""); err != nil {
		t.Fatal(err)
	}
	decision, err = guard.Inspect(ctx, "2001:db8:9:8::abcd", "")
	if err != nil || decision.Banned {
		t.Fatalf("stored /64 unban left a ban: %+v err=%v", decision, err)
	}
}

func TestEmptyFingerprintDoesNotShareAKey(t *testing.T) {
	guard := newTestGuard(3)
	ctx := context.Background()
	if _, err := guard.RecordFailure(ctx, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.RecordFailure(ctx, "not-an-ip", ""); err != nil {
		t.Fatal(err)
	}
	if len(guard.local.entries) != 0 {
		t.Fatalf("empty subjects created keys: %#v", guard.local.entries)
	}
}

type memPolicy struct {
	mu     sync.Mutex
	policy Policy
}

func (m *memPolicy) Load(context.Context) (Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Policy{
		IPWhitelist:   append([]string(nil), m.policy.IPWhitelist...),
		PermanentBans: append([]settingssecurity.AdminLoginBan(nil), m.policy.PermanentBans...),
	}, nil
}

func (m *memPolicy) SavePermanentBans(_ context.Context, bans []settingssecurity.AdminLoginBan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy.PermanentBans = append([]settingssecurity.AdminLoginBan(nil), bans...)
	return nil
}
