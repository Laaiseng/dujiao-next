package adminloginguard

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const localGuardMaxEntries = 10000

type localEntry struct {
	value   int64
	expires time.Time
}

type localStore struct {
	mu      sync.Mutex
	entries map[string]localEntry
}

func newLocalStore() *localStore {
	return &localStore{entries: map[string]localEntry{}}
}

func (s *localStore) incr(key string, window time.Duration, now time.Time, overflow int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	entry, ok := s.entries[key]
	if ok && !now.Before(entry.expires) {
		delete(s.entries, key)
		ok = false
	}
	if !ok {
		if len(s.entries) >= localGuardMaxEntries {
			return overflow
		}
		entry = localEntry{expires: now.Add(window)}
	}
	entry.value++
	s.entries[key] = entry
	return int(entry.value)
}

func (s *localStore) peek(key string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok || !now.Before(entry.expires) {
		return 0
	}
	return int(entry.value)
}

func (s *localStore) banTTL(key string, now time.Time) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok || !now.Before(entry.expires) {
		return 0, false
	}
	seconds := int(entry.expires.Sub(now).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return seconds, true
}

func (s *localStore) setBan(key string, expires, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	if entry, ok := s.entries[key]; ok && now.Before(entry.expires) {
		return
	}
	if _, ok := s.entries[key]; !ok && len(s.entries) >= localGuardMaxEntries {
		return
	}
	s.entries[key] = localEntry{value: 1, expires: expires}
}

func (s *localStore) reserve(key string, expires, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	if entry, ok := s.entries[key]; ok && now.Before(entry.expires) {
		return false
	}
	if _, ok := s.entries[key]; !ok && len(s.entries) >= localGuardMaxEntries {
		return false
	}
	s.entries[key] = localEntry{value: 1, expires: expires}
	return true
}

func (s *localStore) delete(keys ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		delete(s.entries, key)
	}
}

func (s *localStore) expire(now time.Time) {
	for key, entry := range s.entries {
		if !now.Before(entry.expires) {
			delete(s.entries, key)
		}
	}
}

func (g *Guard) incr(ctx context.Context, key string) int {
	if g.redis != nil {
		count, err := g.redis.Incr(ctx, key).Result()
		if err == nil {
			if count == 1 {
				if expireErr := g.redis.Expire(ctx, key, g.window).Err(); expireErr != nil {
					g.warn("admin_login_guard_expire_failed", expireErr)
				}
			}
			return int(count)
		}
		g.warn("admin_login_guard_redis_fallback", err)
	}
	return g.local.incr(key, g.window, g.now(), g.maxFailures)
}

func (g *Guard) peek(ctx context.Context, key string) int {
	if g.redis != nil {
		value, err := g.redis.Get(ctx, key).Result()
		if err == nil {
			count, convErr := strconv.Atoi(value)
			if convErr != nil {
				return 0
			}
			return count
		}
		if err != redis.Nil {
			g.warn("admin_login_guard_redis_fallback", err)
		} else {
			return 0
		}
	}
	return g.local.peek(key, g.now())
}

func (g *Guard) banTTL(ctx context.Context, kind, value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	key := g.banKey(kind, value)
	if g.redis != nil {
		ttl, err := g.redis.TTL(ctx, key).Result()
		if err == nil {
			if ttl < 0 {
				return 0, false
			}
			seconds := int(ttl.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			return seconds, true
		}
		g.warn("admin_login_guard_redis_fallback", err)
	}
	return g.local.banTTL(key, g.now())
}

func (g *Guard) setBan(ctx context.Context, kind, value string) {
	if value == "" {
		return
	}
	key := g.banKey(kind, value)
	if g.redis != nil {
		_, err := g.redis.SetNX(ctx, key, "1", g.banFor).Result()
		if err == nil {
			return
		}
		g.warn("admin_login_guard_redis_fallback", err)
	}
	g.local.setBan(key, g.now().Add(g.banFor), g.now())
}

func (g *Guard) reserve(ctx context.Context, key string, ttl time.Duration) bool {
	if g.redis != nil {
		ok, err := g.redis.SetNX(ctx, key, "1", ttl).Result()
		if err == nil {
			return ok
		}
		g.warn("admin_login_guard_redis_fallback", err)
	}
	return g.local.reserve(key, g.now().Add(ttl), g.now())
}

func (g *Guard) delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	g.local.delete(keys...)
	if g.redis == nil {
		return nil
	}
	if err := g.redis.Del(ctx, keys...).Err(); err != nil && err != redis.Nil {
		g.warn("admin_login_guard_delete_failed", err)
		return err
	}
	return nil
}
