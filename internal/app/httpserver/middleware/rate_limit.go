package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dujiao-next/internal/i18n"
	"github.com/dujiao-next/internal/logger"
	"github.com/dujiao-next/internal/platform/http/response"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimitKeyFunc 生成限流 key 的函数
type RateLimitKeyFunc func(*gin.Context) string

// RateLimitRule 限流规则
type RateLimitRule struct {
	Prefix        string
	WindowSeconds int
	MaxRequests   int
	BlockSeconds  int
	MessageKey    string
	// ResetOnSuccess 在业务成功（HTTP 200 且 status_code=0）后删除计数。
	// 登录接口用来实现“失败累计、成功清零”；超限请求在进入处理函数前就被拒绝。
	ResetOnSuccess bool
}

var rateLimitScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
	redis.call("EXPIRE", KEYS[1], ARGV[1])
end
if tonumber(ARGV[2]) > 0 and tonumber(ARGV[3]) > 0 and current == tonumber(ARGV[2]) + 1 then
	redis.call("EXPIRE", KEYS[1], ARGV[3])
end
local ttl = redis.call("TTL", KEYS[1])
return {current, ttl}
`)

type localRateLimitEntry struct {
	count     int64
	expiresAt time.Time
}

type localRateLimiter struct {
	mu                      sync.Mutex
	entries                 map[string]localRateLimitEntry
	lastCapacityWarningAt   time.Time
	lastRedisFallbackWarnAt time.Time
}

const localRateLimitMaxEntries = 10000
const localRateLimitWarningInterval = time.Minute

func (l *localRateLimiter) increment(key string, rule RateLimitRule, now time.Time) (int64, int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[string]localRateLimitEntry)
	}

	entry, exists := l.entries[key]
	if exists && (entry.expiresAt.IsZero() || !now.Before(entry.expiresAt)) {
		delete(l.entries, key)
		exists = false
	}
	if !exists {
		if len(l.entries) >= localRateLimitMaxEntries {
			for existingKey, existing := range l.entries {
				if existing.expiresAt.IsZero() || !now.Before(existing.expiresAt) {
					delete(l.entries, existingKey)
				}
			}
		}
		if len(l.entries) >= localRateLimitMaxEntries {
			// 不淘汰仍在窗口内的计数器；容量耗尽时仅拒绝新的 key，
			// 防止攻击者用高基数 IP/标识绕过已有 key 的频率限制。
			ttl := int64(rule.WindowSeconds)
			if ttl < 1 {
				ttl = 1
			}
			shouldWarn := l.lastCapacityWarningAt.IsZero() ||
				now.Sub(l.lastCapacityWarningAt) >= localRateLimitWarningInterval
			if shouldWarn {
				l.lastCapacityWarningAt = now
			}
			return int64(rule.MaxRequests) + 1, ttl, shouldWarn
		}
		entry = localRateLimitEntry{expiresAt: now.Add(time.Duration(rule.WindowSeconds) * time.Second)}
	}
	entry.count++
	if entry.count == int64(rule.MaxRequests)+1 && rule.BlockSeconds > 0 {
		entry.expiresAt = now.Add(time.Duration(rule.BlockSeconds) * time.Second)
	}
	l.entries[key] = entry
	ttl := int64(entry.expiresAt.Sub(now).Seconds())
	if ttl < 1 {
		ttl = 1
	}
	return entry.count, ttl, false
}

func (l *localRateLimiter) delete(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		return
	}
	delete(l.entries, key)
}

func (l *localRateLimiter) shouldWarnRedisFallback(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lastRedisFallbackWarnAt.IsZero() &&
		now.Sub(l.lastRedisFallbackWarnAt) < localRateLimitWarningInterval {
		return false
	}
	l.lastRedisFallbackWarnAt = now
	return true
}

// RateLimitMiddleware Redis 频率限制中间件。
// Redis 未配置或运行时暂时不可用时使用进程内兜底；该兜底仅对当前实例生效，
// 多实例部署必须配置共享 Redis 才能获得全局一致的计数。Redis 故障降级和
// 本地容量耗尽都会输出节流后的 warning，避免故障期间产生日志洪泛。
func RateLimitMiddleware(client *redis.Client, rule RateLimitRule, keyFunc RateLimitKeyFunc) gin.HandlerFunc {
	return rateLimitMiddleware(client, rule, keyFunc)
}

// RateLimitMiddlewareKeys 用同一窗口、次数和封禁对多个 key 分别计数。
// 任一 key 超限即返回 429。同一次请求计算出相同存储 key 时只计一次。
func RateLimitMiddlewareKeys(client *redis.Client, rule RateLimitRule, keyFuncs ...RateLimitKeyFunc) gin.HandlerFunc {
	if len(keyFuncs) == 0 {
		keyFuncs = []RateLimitKeyFunc{KeyByIP}
	}
	return rateLimitMiddleware(client, rule, keyFuncs...)
}

type rateLimitCount struct {
	key            string
	count          int64
	ttlSeconds     int64
	countedInRedis bool
}

func rateLimitMiddleware(client *redis.Client, rule RateLimitRule, keyFuncs ...RateLimitKeyFunc) gin.HandlerFunc {
	local := &localRateLimiter{}
	return func(c *gin.Context) {
		if rule.WindowSeconds <= 0 || rule.MaxRequests <= 0 || len(keyFuncs) == 0 {
			c.Next()
			return
		}

		now := time.Now()
		seen := make(map[string]struct{}, len(keyFuncs))
		counted := make([]rateLimitCount, 0, len(keyFuncs))
		for _, keyFunc := range keyFuncs {
			key := rateLimitStorageKey(c, rule, keyFunc)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			hit := acquireRateLimit(c, client, local, rule, key, now)
			counted = append(counted, hit)
			if hit.count > int64(rule.MaxRequests) {
				rejectRateLimited(c, rule, hit.ttlSeconds)
				return
			}
		}

		if !rule.ResetOnSuccess {
			c.Next()
			return
		}
		capture := &limitedBodyWriter{ResponseWriter: c.Writer}
		c.Writer = capture
		c.Next()
		if !isBusinessSuccess(capture) {
			return
		}
		for _, hit := range counted {
			clearRateLimitKey(client, local, c, hit.key, hit.countedInRedis)
		}
	}
}

func rateLimitStorageKey(c *gin.Context, rule RateLimitRule, keyFunc RateLimitKeyFunc) string {
	key := ""
	if keyFunc != nil {
		key = strings.TrimSpace(keyFunc(c))
	}
	if key == "" {
		key = c.ClientIP()
	}
	if rule.Prefix != "" {
		key = fmt.Sprintf("%s:%s", rule.Prefix, key)
	}
	return key
}

func acquireRateLimit(c *gin.Context, client *redis.Client, local *localRateLimiter, rule RateLimitRule, key string, now time.Time) rateLimitCount {
	hit := rateLimitCount{key: key}
	incrementLocal := func() {
		var capacityWarning bool
		hit.count, hit.ttlSeconds, capacityWarning = local.increment(key, rule, now)
		hit.countedInRedis = false
		if capacityWarning {
			logger.Warnw(
				"rate_limit_local_capacity_exhausted",
				"prefix", rule.Prefix,
				"max_entries", localRateLimitMaxEntries,
				"window_seconds", rule.WindowSeconds,
			)
		}
	}
	if client == nil {
		incrementLocal()
		return hit
	}
	result, err := rateLimitScript.Run(
		c.Request.Context(),
		client,
		[]string{key},
		rule.WindowSeconds,
		rule.MaxRequests,
		rule.BlockSeconds,
	).Result()
	if err != nil {
		if local.shouldWarnRedisFallback(now) {
			logger.Warnw("rate_limit_redis_fallback", "prefix", rule.Prefix, "error", err)
		}
		incrementLocal()
		return hit
	}
	values, ok := result.([]interface{})
	if !ok || len(values) < 2 {
		if local.shouldWarnRedisFallback(now) {
			logger.Warnw(
				"rate_limit_redis_fallback",
				"prefix", rule.Prefix,
				"error", fmt.Sprintf("unexpected result shape %T", result),
			)
		}
		incrementLocal()
		return hit
	}
	hit.count, ok = toInt64(values[0])
	if !ok {
		if local.shouldWarnRedisFallback(now) {
			logger.Warnw(
				"rate_limit_redis_fallback",
				"prefix", rule.Prefix,
				"error", fmt.Sprintf("invalid count type %T", values[0]),
			)
		}
		incrementLocal()
		return hit
	}
	hit.ttlSeconds, _ = toInt64(values[1])
	hit.countedInRedis = true
	return hit
}

func rejectRateLimited(c *gin.Context, rule RateLimitRule, ttlSeconds int64) {
	waitSeconds := int(ttlSeconds)
	if waitSeconds < 1 {
		waitSeconds = rule.WindowSeconds
	}
	if waitSeconds < 1 {
		waitSeconds = 1
	}
	msgKey := strings.TrimSpace(rule.MessageKey)
	if msgKey == "" {
		msgKey = "error.rate_limited"
	}
	msg := i18n.Sprintf(i18n.ResolveLocale(c), msgKey, waitSeconds)
	if isChannelAPIRequest(c) {
		response.ChannelError(c, 429, response.CodeTooManyRequests, msg, "rate_limit_exceeded")
	} else {
		response.ErrorWithHTTPStatus(c, 429, response.CodeTooManyRequests, msg)
	}
	c.Abort()
}

func clearRateLimitKey(client *redis.Client, local *localRateLimiter, c *gin.Context, key string, countedInRedis bool) {
	if local != nil {
		local.delete(key)
	}
	if !countedInRedis || client == nil || c == nil || c.Request == nil {
		return
	}
	if err := client.Del(c.Request.Context(), key).Err(); err != nil && err != redis.Nil {
		logger.Warnw("rate_limit_reset_failed", "error", err)
	}
}

const rateLimitSuccessBodyLimit = 1 << 16

// limitedBodyWriter 复制一小段响应体，用来识别登录是否业务成功。
type limitedBodyWriter struct {
	gin.ResponseWriter
	body bytes.Buffer
}

func (w *limitedBodyWriter) Write(b []byte) (int, error) {
	w.capture(b)
	return w.ResponseWriter.Write(b)
}

func (w *limitedBodyWriter) WriteString(s string) (int, error) {
	w.capture([]byte(s))
	return w.ResponseWriter.WriteString(s)
}

func (w *limitedBodyWriter) capture(b []byte) {
	if w.body.Len() >= rateLimitSuccessBodyLimit {
		return
	}
	remain := rateLimitSuccessBodyLimit - w.body.Len()
	if len(b) > remain {
		b = b[:remain]
	}
	_, _ = w.body.Write(b)
}

func isBusinessSuccess(w *limitedBodyWriter) bool {
	if w == nil || !w.Written() || w.Status() != http.StatusOK {
		return false
	}
	var payload struct {
		StatusCode int `json:"status_code"`
	}
	if err := json.Unmarshal(w.body.Bytes(), &payload); err != nil {
		return false
	}
	return payload.StatusCode == 0
}

func isChannelAPIRequest(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	return strings.HasPrefix(c.Request.URL.Path, "/api/v1/channel")
}

// KeyByIP 使用 IP 作为限流 key
func KeyByIP(c *gin.Context) string {
	return c.ClientIP()
}

// KeyByUserIDAndIP isolates authenticated mutation limits by both account and
// source IP. It falls back to IP when authentication context is unavailable.
func KeyByUserIDAndIP(c *gin.Context) string {
	if c == nil {
		return ""
	}
	userID, exists := c.Get("user_id")
	if !exists {
		return c.ClientIP()
	}
	return fmt.Sprintf("%v|%s", userID, c.ClientIP())
}

// KeyByIPAndHeader 以 "IP|header 值" 作为限流 key。
// 限流位于鉴权之前，header 未经校验，因此计数必须同时绑定来源 IP。
func KeyByIPAndHeader(header string) RateLimitKeyFunc {
	return func(c *gin.Context) string {
		value := c.GetHeader(header)
		if len(value) > 128 {
			value = value[:128]
		}
		if value == "" {
			return c.ClientIP()
		}
		return c.ClientIP() + "|" + value
	}
}

// KeyByUpstreamApiKey 使用 "IP|上游 API Key" 作为限流 key
func KeyByUpstreamApiKey(c *gin.Context) string {
	return KeyByIPAndHeader("Dujiao-Next-Api-Key")(c)
}

// KeyByIPAndJSONField 使用 IP + JSON 字段作为限流 key
func KeyByIPAndJSONField(field string) RateLimitKeyFunc {
	return KeyByIPAndJSONFields(field)
}

// KeyByIPAndJSONFields 依次读取 JSON 字符串字段，用第一个非空值与 IP 组成限流 key。
func KeyByIPAndJSONFields(fields ...string) RateLimitKeyFunc {
	return func(c *gin.Context) string {
		if c == nil {
			return ""
		}
		values := readJSONStringFields(c, fields...)
		account := ""
		for _, field := range fields {
			account = strings.ToLower(strings.TrimSpace(values[field]))
			if account != "" {
				break
			}
		}
		return joinAccountAndIP(account, c.ClientIP())
	}
}

// KeyByIPAndAccount 使用 IP + 登录账号（email / username / account）作为限流 key。
// 账号会转成小写并截断，避免同一账号用大小写或超长字段绕过计数。
func KeyByIPAndAccount(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return KeyByIPAndJSONFields("email", "username", "account")(c)
}

func joinAccountAndIP(account, ip string) string {
	if len(account) > 254 {
		account = account[:254]
	}
	if account == "" {
		return ip
	}
	return account + "|" + ip
}

func readJSONField(c *gin.Context, field string) string {
	return readJSONStringFields(c, field)[field]
}

func readJSONStringFields(c *gin.Context, fields ...string) map[string]string {
	found := make(map[string]string, len(fields))
	if c == nil || c.Request == nil || c.Request.Body == nil || len(fields) == 0 {
		return found
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return found
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	if len(body) == 0 {
		return found
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return found
	}
	for _, field := range fields {
		value, ok := payload[field]
		if !ok {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		found[field] = strings.TrimSpace(text)
	}
	return found
}

func toInt64(value interface{}) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int16:
		return int64(v), true
	case int8:
		return int64(v), true
	case uint64:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint16:
		return int64(v), true
	case uint8:
		return int64(v), true
	case float64:
		return int64(v), true
	case float32:
		return int64(v), true
	default:
		return 0, false
	}
}
