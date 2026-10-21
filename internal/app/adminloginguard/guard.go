// Package adminloginguard 实现后台登录失败计数与临时封禁。
// 只统计密码错误和 2FA 验证失败。已封禁的主体只做存在性检查，不再 INCR。
// 成功登录清掉失败计数，不清已经生效的封禁。永久封禁只来自手动操作。
package adminloginguard

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dujiao-next/internal/constants"
	"github.com/dujiao-next/internal/logger"
	settingssecurity "github.com/dujiao-next/internal/modules/settings/schema/security"
	"github.com/dujiao-next/internal/shared/jsonmap"
	"github.com/dujiao-next/internal/shared/netaddr"

	"github.com/redis/go-redis/v9"
)

const (
	defaultWindow      = 15 * time.Minute
	defaultBanFor      = time.Hour
	defaultMaxFailures = 5
	defaultPolicyTTL   = 10 * time.Second
	auditInterval      = time.Minute

	kindIP = settingssecurity.AdminLoginBanKindIP
	kindFP = settingssecurity.AdminLoginBanKindFingerprint

	// HeaderFingerprint 是后台登录页附带的浏览器指纹。
	HeaderFingerprint = "X-Login-Fingerprint"
	// ContextFingerprintKey 保存本次请求已清洗的指纹，空字符串表示跳过指纹维度。
	ContextFingerprintKey = "admin_login_guard_fingerprint"
	// ContextWhitelistedKey 为 true 时本次请求不计数、不封禁。
	ContextWhitelistedKey = "admin_login_guard_whitelisted"
)

var (
	// ErrEmptySubject 表示解封 / 永久封禁没有可用的 IP 或指纹。
	ErrEmptySubject = errors.New("admin login ban subject is empty")
	// ErrPolicyUnavailable 表示没有可写入的热更新设置。
	ErrPolicyUnavailable = errors.New("admin login guard policy store is unavailable")
)

// Failure 是一次失败计数的结果。Banned 为 true 时调用方应拒绝，且不得再递增。
type Failure struct {
	IPFails           int
	FPFails           int
	Banned            bool
	Permanent         bool
	RetryAfterSeconds int
	Fingerprint       string
	Dimension         string
}

// Subject 是一次登录请求参与封禁判断的主体。
type Subject struct {
	RawIP        string
	NormalizedIP string
	Fingerprint  string
}

// Decision 是进入密码校验之前的检查结果。
type Decision struct {
	Subject           Subject
	Whitelisted       bool
	Banned            bool
	Permanent         bool
	Dimension         string
	RetryAfterSeconds int
	IPFails           int
	FPFails           int
	Username          string
}

// UnbanResult 描述一次解封碰到的存储状态。
type UnbanResult struct {
	RedisUnavailable bool
}

// Policy 是热更新白名单与永久封禁。
type Policy struct {
	IPWhitelist   []string
	PermanentBans []settingssecurity.AdminLoginBan
}

// PolicySource 读取并更新热更新策略。
type PolicySource interface {
	Load(ctx context.Context) (Policy, error)
	SavePermanentBans(ctx context.Context, bans []settingssecurity.AdminLoginBan) error
}

type settingsAPI interface {
	GetAdminLoginGuardConfig() (settingssecurity.AdminLoginGuardConfig, error)
	Update(key string, value map[string]interface{}) (jsonmap.JSON, error)
}

type settingsPolicy struct {
	settings settingsAPI
}

func (s settingsPolicy) Load(context.Context) (Policy, error) {
	cfg, err := s.settings.GetAdminLoginGuardConfig()
	if err != nil {
		return Policy{}, err
	}
	return Policy{IPWhitelist: cfg.IPWhitelist, PermanentBans: cfg.PermanentBans}, nil
}

func (s settingsPolicy) SavePermanentBans(_ context.Context, bans []settingssecurity.AdminLoginBan) error {
	cfg, err := s.settings.GetAdminLoginGuardConfig()
	if err != nil {
		return err
	}
	cfg.PermanentBans = bans
	_, err = s.settings.Update(constants.SettingKeyAdminLoginGuardConfig, map[string]interface{}(settingssecurity.EncodeAdminLoginGuardConfig(cfg)))
	return err
}

// Options 构造后台登录封禁器。
type Options struct {
	Redis           *redis.Client
	Prefix          string
	Window          time.Duration
	MaxFailures     int
	BanFor          time.Duration
	StaticWhitelist []string
	Settings        settingsAPI
	Now             func() time.Time
	// PolicyTTL 小于 0 时每次都读热更新设置。0 使用默认 10 秒缓存。
	PolicyTTL time.Duration
}

// Guard 在 Redis 不可用时退化为进程内计数，语义与可用时一致，但只覆盖当前进程。
type Guard struct {
	redis           *redis.Client
	prefix          string
	window          time.Duration
	maxFailures     int
	banFor          time.Duration
	staticWhitelist []string
	policies        PolicySource
	now             func() time.Time
	policyTTL       time.Duration
	local           *localStore

	policyMu     sync.Mutex
	policyCached Policy
	policyAt     time.Time

	warnMu   sync.Mutex
	lastWarn time.Time
}

func New(opts Options) *Guard {
	window := opts.Window
	if window <= 0 {
		window = defaultWindow
	}
	banFor := opts.BanFor
	if banFor <= 0 {
		banFor = defaultBanFor
	}
	maxFailures := opts.MaxFailures
	if maxFailures <= 0 {
		maxFailures = defaultMaxFailures
	}
	prefix := strings.TrimSpace(opts.Prefix)
	if prefix == "" {
		prefix = constants.RedisPrefixDefault
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	policyTTL := defaultPolicyTTL
	if opts.PolicyTTL < 0 {
		policyTTL = 0
	} else if opts.PolicyTTL > 0 {
		policyTTL = opts.PolicyTTL
	}
	var policies PolicySource
	if opts.Settings != nil {
		policies = settingsPolicy{settings: opts.Settings}
	}
	return &Guard{
		redis:           opts.Redis,
		prefix:          prefix,
		window:          window,
		maxFailures:     maxFailures,
		banFor:          banFor,
		staticWhitelist: append([]string(nil), opts.StaticWhitelist...),
		policies:        policies,
		now:             now,
		policyTTL:       policyTTL,
		local:           newLocalStore(),
	}
}

// Inspect 只读取封禁状态，不增加失败计数。
func (g *Guard) Inspect(ctx context.Context, rawIP, rawFingerprint string) (Decision, error) {
	if g == nil {
		return Decision{}, nil
	}
	ctx = background(ctx)
	subject := g.prepare(rawIP, rawFingerprint)
	decision := Decision{Subject: subject}
	allow, bans := g.currentPolicy(ctx)
	if allow.contains(subject.RawIP) {
		decision.Whitelisted = true
		return decision, nil
	}
	if permanentHit(bans, kindIP, subject.NormalizedIP) {
		decision.Banned = true
		decision.Permanent = true
		decision.Dimension = kindIP
		decision.IPFails, decision.FPFails = g.peekFails(ctx, subject)
		return decision, nil
	}
	if permanentHit(bans, kindFP, subject.Fingerprint) {
		decision.Banned = true
		decision.Permanent = true
		decision.Dimension = kindFP
		decision.IPFails, decision.FPFails = g.peekFails(ctx, subject)
		return decision, nil
	}
	if ttl, ok := g.banTTL(ctx, kindIP, subject.NormalizedIP); ok {
		decision.Banned = true
		decision.Dimension = kindIP
		decision.RetryAfterSeconds = ttl
		decision.IPFails, decision.FPFails = g.peekFails(ctx, subject)
		return decision, nil
	}
	if ttl, ok := g.banTTL(ctx, kindFP, subject.Fingerprint); ok {
		decision.Banned = true
		decision.Dimension = kindFP
		decision.RetryAfterSeconds = ttl
		decision.IPFails, decision.FPFails = g.peekFails(ctx, subject)
		return decision, nil
	}
	decision.IPFails, decision.FPFails = g.peekFails(ctx, subject)
	return decision, nil
}

// RecordFailure 为未封禁、非白名单的主体增加失败次数。已封禁时直接返回，不 INCR。
func (g *Guard) RecordFailure(ctx context.Context, rawIP, rawFingerprint string) (Failure, error) {
	decision, err := g.Inspect(ctx, rawIP, rawFingerprint)
	result := Failure{
		IPFails:           decision.IPFails,
		FPFails:           decision.FPFails,
		Banned:            decision.Banned,
		Permanent:         decision.Permanent,
		RetryAfterSeconds: decision.RetryAfterSeconds,
		Fingerprint:       decision.Subject.Fingerprint,
		Dimension:         decision.Dimension,
	}
	if err != nil || g == nil || decision.Whitelisted || decision.Banned {
		return result, err
	}
	ctx = background(ctx)
	subject := decision.Subject
	if subject.NormalizedIP != "" {
		count := g.incr(ctx, g.failKey(kindIP, subject.NormalizedIP))
		result.IPFails = count
		if count >= g.maxFailures {
			g.setBan(ctx, kindIP, subject.NormalizedIP)
			result.Banned = true
			result.Dimension = kindIP
			result.RetryAfterSeconds = g.banSeconds()
		}
	}
	if subject.Fingerprint != "" {
		count := g.incr(ctx, g.failKey(kindFP, subject.Fingerprint))
		result.FPFails = count
		if count >= g.maxFailures {
			g.setBan(ctx, kindFP, subject.Fingerprint)
			result.Banned = true
			if result.Dimension == "" {
				result.Dimension = kindFP
			}
			if result.RetryAfterSeconds < g.banSeconds() {
				result.RetryAfterSeconds = g.banSeconds()
			}
		}
	}
	return result, nil
}

// ClearFailures 删除该 IP 与指纹的失败计数，不删除封禁键。
func (g *Guard) ClearFailures(ctx context.Context, rawIP, rawFingerprint string) error {
	if g == nil {
		return nil
	}
	subject := g.prepare(rawIP, rawFingerprint)
	return g.delete(background(ctx), g.failKeys(subject)...)
}

// BanPermanent 把 IP 和 / 或指纹写入热更新永久封禁。临时阈值不会走到这里。
func (g *Guard) BanPermanent(ctx context.Context, rawIP, rawFingerprint string) error {
	if g == nil || g.policies == nil {
		return ErrPolicyUnavailable
	}
	subject := g.prepare(rawIP, rawFingerprint)
	if subject.NormalizedIP == "" && subject.Fingerprint == "" {
		return ErrEmptySubject
	}
	ctx = background(ctx)
	policy, err := g.policies.Load(ctx)
	if err != nil {
		return err
	}
	bans := append([]settingssecurity.AdminLoginBan(nil), policy.PermanentBans...)
	if subject.NormalizedIP != "" && !permanentHit(bans, kindIP, subject.NormalizedIP) {
		bans = append(bans, settingssecurity.AdminLoginBan{Kind: kindIP, Value: subject.NormalizedIP})
	}
	if subject.Fingerprint != "" && !permanentHit(bans, kindFP, subject.Fingerprint) {
		bans = append(bans, settingssecurity.AdminLoginBan{Kind: kindFP, Value: subject.Fingerprint})
	}
	if err := g.policies.SavePermanentBans(ctx, bans); err != nil {
		return err
	}
	g.invalidatePolicy()
	return nil
}

// Unban 删除临时封禁、失败计数，并移出永久封禁名单。
func (g *Guard) Unban(ctx context.Context, rawIP, rawFingerprint string) error {
	_, err := g.UnbanDetails(ctx, rawIP, rawFingerprint)
	return err
}

// UnbanDetails 与 Unban 相同，并说明 Redis 是否不可用。
func (g *Guard) UnbanDetails(ctx context.Context, rawIP, rawFingerprint string) (UnbanResult, error) {
	result := UnbanResult{}
	if g == nil {
		return result, ErrPolicyUnavailable
	}
	result.RedisUnavailable = g.redis == nil
	subject := g.prepare(rawIP, rawFingerprint)
	if subject.NormalizedIP == "" && subject.Fingerprint == "" {
		return result, ErrEmptySubject
	}
	ctx = background(ctx)
	keys := append(g.failKeys(subject), g.banKeys(subject)...)
	keys = append(keys, g.auditKeys(subject)...)
	delErr := g.delete(ctx, keys...)
	permErr := g.removePermanent(ctx, subject)
	if delErr != nil {
		return result, delErr
	}
	return result, permErr
}

// AllowAudit 限制同一主体的「已封禁」审计每分钟最多一条，避免洪水写库。
func (g *Guard) AllowAudit(ctx context.Context, subject Subject) bool {
	if g == nil {
		return false
	}
	identity := auditIdentity(subject)
	return g.reserve(background(ctx), g.auditKey(identity), auditInterval)
}

func (g *Guard) prepare(rawIP, rawFingerprint string) Subject {
	return Subject{
		RawIP:        strings.TrimSpace(rawIP),
		NormalizedIP: netaddr.NormalizeRiskIP(rawIP),
		Fingerprint:  settingssecurity.NormalizeAdminLoginFingerprint(rawFingerprint),
	}
}

func (g *Guard) banSeconds() int {
	seconds := int(g.banFor.Seconds())
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (g *Guard) currentPolicy(ctx context.Context) (ipAllowlist, []settingssecurity.AdminLoginBan) {
	hot := g.cachedPolicy(ctx)
	entries := make([]string, 0, len(g.staticWhitelist)+len(hot.IPWhitelist))
	entries = append(entries, g.staticWhitelist...)
	entries = append(entries, hot.IPWhitelist...)
	return parseAllowlist(entries), hot.PermanentBans
}

func (g *Guard) cachedPolicy(ctx context.Context) Policy {
	if g.policies == nil {
		return Policy{}
	}
	now := g.now()
	g.policyMu.Lock()
	if g.policyTTL > 0 && !g.policyAt.IsZero() && now.Sub(g.policyAt) < g.policyTTL {
		cached := g.policyCached
		g.policyMu.Unlock()
		return cached
	}
	g.policyMu.Unlock()

	loaded, err := g.policies.Load(ctx)
	if err != nil {
		g.warn("admin_login_guard_policy_failed", err)
		g.policyMu.Lock()
		stale := g.policyCached
		g.policyMu.Unlock()
		return stale
	}
	g.policyMu.Lock()
	g.policyCached = loaded
	g.policyAt = now
	g.policyMu.Unlock()
	return loaded
}

func (g *Guard) invalidatePolicy() {
	g.policyMu.Lock()
	g.policyAt = time.Time{}
	g.policyMu.Unlock()
}

func (g *Guard) removePermanent(ctx context.Context, subject Subject) error {
	if g.policies == nil {
		return nil
	}
	policy, err := g.policies.Load(ctx)
	if err != nil {
		return err
	}
	filtered := make([]settingssecurity.AdminLoginBan, 0, len(policy.PermanentBans))
	changed := false
	for _, ban := range policy.PermanentBans {
		if subject.NormalizedIP != "" && ban.Kind == kindIP && ban.Value == subject.NormalizedIP {
			changed = true
			continue
		}
		if subject.Fingerprint != "" && ban.Kind == kindFP && ban.Value == subject.Fingerprint {
			changed = true
			continue
		}
		filtered = append(filtered, ban)
	}
	if !changed {
		return nil
	}
	if err := g.policies.SavePermanentBans(ctx, filtered); err != nil {
		return err
	}
	g.invalidatePolicy()
	return nil
}

func (g *Guard) peekFails(ctx context.Context, subject Subject) (int, int) {
	ipFails := 0
	fpFails := 0
	if subject.NormalizedIP != "" {
		ipFails = g.peek(ctx, g.failKey(kindIP, subject.NormalizedIP))
	}
	if subject.Fingerprint != "" {
		fpFails = g.peek(ctx, g.failKey(kindFP, subject.Fingerprint))
	}
	return ipFails, fpFails
}

func (g *Guard) failKeys(subject Subject) []string {
	keys := make([]string, 0, 2)
	if subject.NormalizedIP != "" {
		keys = append(keys, g.failKey(kindIP, subject.NormalizedIP))
	}
	if subject.Fingerprint != "" {
		keys = append(keys, g.failKey(kindFP, subject.Fingerprint))
	}
	return keys
}

func (g *Guard) banKeys(subject Subject) []string {
	keys := make([]string, 0, 2)
	if subject.NormalizedIP != "" {
		keys = append(keys, g.banKey(kindIP, subject.NormalizedIP))
	}
	if subject.Fingerprint != "" {
		keys = append(keys, g.banKey(kindFP, subject.Fingerprint))
	}
	return keys
}

func (g *Guard) auditKeys(subject Subject) []string {
	keys := make([]string, 0, 2)
	if subject.NormalizedIP != "" {
		keys = append(keys, g.auditKey("ip:"+subject.NormalizedIP))
	}
	if subject.Fingerprint != "" {
		keys = append(keys, g.auditKey("fp:"+subject.Fingerprint))
	}
	return keys
}

func (g *Guard) failKey(kind, value string) string {
	return g.prefix + ":loginfail:v1:admin:" + kind + ":" + value
}

func (g *Guard) banKey(kind, value string) string {
	return g.prefix + ":loginban:v1:admin:" + kind + ":" + value
}

func (g *Guard) auditKey(identity string) string {
	return g.prefix + ":loginban:v1:admin:audit:" + identity
}

func auditIdentity(subject Subject) string {
	if subject.NormalizedIP != "" {
		return "ip:" + subject.NormalizedIP
	}
	if subject.Fingerprint != "" {
		return "fp:" + subject.Fingerprint
	}
	return "unknown"
}

func permanentHit(bans []settingssecurity.AdminLoginBan, kind, value string) bool {
	if value == "" {
		return false
	}
	for _, ban := range bans {
		if ban.Kind == kind && ban.Value == value {
			return true
		}
	}
	return false
}

func background(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (g *Guard) warn(message string, err error) {
	if err == nil {
		return
	}
	now := g.now()
	g.warnMu.Lock()
	if !g.lastWarn.IsZero() && now.Sub(g.lastWarn) < auditInterval {
		g.warnMu.Unlock()
		return
	}
	g.lastWarn = now
	g.warnMu.Unlock()
	logger.Warnw(message, "error", err)
}

type ipAllowlist struct {
	exact map[string]struct{}
	nets  []*net.IPNet
}

func parseAllowlist(entries []string) ipAllowlist {
	allow := ipAllowlist{exact: map[string]struct{}{}}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			allow.exact[ip.String()] = struct{}{}
			if v4 := ip.To4(); v4 != nil {
				allow.exact[v4.String()] = struct{}{}
			}
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err == nil && network != nil {
			allow.nets = append(allow.nets, network)
		}
	}
	return allow
}

func (a ipAllowlist) contains(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	if _, ok := a.exact[ip.String()]; ok {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if _, ok := a.exact[v4.String()]; ok {
			return true
		}
	}
	for _, network := range a.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
