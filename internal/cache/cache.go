package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

const MaxSecretVersionSize = 64 * 1024

// ErrNotFound reports that a cache entry does not exist in the backing store.
// Store implementations must return it rather than an autocert-specific error.
var ErrNotFound = errors.New("cache entry not found")

// Store is the provider-agnostic secret backend used by Cache.
type Store interface {
	Find(ctx context.Context, name string) (id string, err error)
	Read(ctx context.Context, id string) ([]byte, error)
	Create(ctx context.Context, name string) (id string, err error)
	Write(ctx context.Context, id string, data []byte) error
	DisableLatest(ctx context.Context, id string) error
}

// Cache implements autocert.Cache on top of an encrypted secret store.
type Cache struct {
	store  Store
	prefix string
	mu     sync.Mutex
}

func New(store Store, prefix string) *Cache {
	return &Cache{store: store, prefix: prefix}
}

func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	id, err := c.store.Find(ctx, c.SecretName(key))
	if errors.Is(err, ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("find secret for cache key %q: %w", key, err)
	}
	data, err := c.store.Read(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("read secret for cache key %q: %w", key, err)
	}
	return data, nil
}

func (c *Cache) Put(ctx context.Context, key string, data []byte) error {
	if len(data) > MaxSecretVersionSize {
		return fmt.Errorf("cache data for %q exceeds Secret Manager's 64 KiB version limit", key)
	}

	// Avoid duplicate secret creation and version interleaving in this process.
	c.mu.Lock()
	defer c.mu.Unlock()
	name := c.SecretName(key)
	id, err := c.store.Find(ctx, name)
	if errors.Is(err, ErrNotFound) {
		id, err = c.store.Create(ctx, name)
	}
	if err != nil {
		return fmt.Errorf("prepare secret for cache key %q: %w", key, err)
	}
	if err := c.store.Write(ctx, id, data); err != nil {
		return fmt.Errorf("write secret for cache key %q: %w", key, err)
	}
	return nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	id, err := c.store.Find(ctx, c.SecretName(key))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find secret for cache key %q: %w", key, err)
	}
	if err := c.store.DisableLatest(ctx, id); err != nil {
		return fmt.Errorf("disable secret for cache key %q: %w", key, err)
	}
	return nil
}

func (c *Cache) SecretName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return c.prefix + "-" + hex.EncodeToString(sum[:])
}
