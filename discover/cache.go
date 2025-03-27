package discover

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type jwksCacheEntry struct {
	value   []byte
	expires time.Time
}

type JwksFetchWithExpiresFunc func(ctx context.Context, issuer string) ([]byte, time.Time, error)

// JwksCache caches JWKS responses by issuer. It is safe for use by multiple
// concurrent goroutines.
//
// This is a very simple implementation with the following caveats:
//   - no size limit, since the set of issuers in use is expected to be small
//   - uses a single RWMutex with double-checked locking idiom
//   - entries are expired according to the Expires header only
//   - i.e., Cache-Control is ignored, because it is complicated to honor
//   - entries are not refreshed until they're fetched after they've expired
type JwksCache struct {
	fetcher JwksFetchWithExpiresFunc
	clock   func() time.Time

	mutex   sync.RWMutex // guards entries
	entries map[string]jwksCacheEntry
}

// NewJwksCache creates a new JwksCache using fetcher to obtain values on
// cache misses and time.Now as the clock.
func NewJwksCache(fetcher JwksFetchWithExpiresFunc) *JwksCache {
	return NewJwksCacheWithClock(fetcher, time.Now)
}

// NewJwksCacheWithClock creates a new JwksCache using fetcher to obtain
// values on cache misses and the given clock.
func NewJwksCacheWithClock(fetcher JwksFetchWithExpiresFunc, clock func() time.Time) *JwksCache {
	return &JwksCache{
		fetcher: fetcher,
		clock:   clock,
		entries: make(map[string]jwksCacheEntry),
	}
}

// GetJwksByIssuer is a JwksFetchFunc that resolves values from the cache
// first.
func (c *JwksCache) GetJwksByIssuer(ctx context.Context, issuer string) ([]byte, error) {
	now := c.clock()
	c.mutex.RLock()
	value, ok := c.getEntryUnchecked(now, issuer)
	c.mutex.RUnlock()
	if ok {
		return value, nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	value, ok = c.getEntryUnchecked(now, issuer)
	if ok {
		return value, nil
	}
	value, expires, err := c.fetcher(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("fetching updated JWKS after cache miss: %w", err)
	}
	entry := jwksCacheEntry{
		value:   value,
		expires: expires,
	}
	c.entries[issuer] = entry
	return entry.value, nil
}

func (c *JwksCache) getEntryUnchecked(now time.Time, issuer string) (value []byte, ok bool) {
	entry, ok := c.entries[issuer]
	if !ok {
		return nil, false
	}
	if now.After(entry.expires) {
		return nil, false
	}
	return entry.value, true
}
