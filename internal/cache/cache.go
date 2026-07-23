package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

const MaxSecretVersionSize = 64 * 1024

// ErrNotFound reports that a cache entry does not exist in the backing store.
// Store implementations must return it rather than an autocert-specific error.
var ErrNotFound = errors.New("cache entry not found")

// Kind classifies an autocert cache entry by its purpose.
type Kind string

const (
	KindAccount Kind = "account"
	KindCert    Kind = "cert"
	KindHTTP01  Kind = "http01"
	KindALPN    Kind = "alpn"
)

// SecretType is the provider-agnostic secret type to create in the backing store.
type SecretType string

const (
	SecretTypeOpaque      SecretType = "opaque"
	SecretTypeCertificate SecretType = "certificate"
)

// SecretMeta describes a cache entry's backend identity.
type SecretMeta struct {
	Name string
	Type SecretType
}

// Store is the provider-agnostic secret backend used by Cache.
type Store interface {
	Find(ctx context.Context, name string) (id string, err error)
	Read(ctx context.Context, id string) ([]byte, error)
	Create(ctx context.Context, meta SecretMeta) (id string, err error)
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
	id, err := c.store.Find(ctx, c.Meta(key).Name)
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
	meta := c.Meta(key)
	id, err := c.store.Find(ctx, meta.Name)
	if errors.Is(err, ErrNotFound) {
		id, err = c.store.Create(ctx, meta)
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
	id, err := c.store.Find(ctx, c.Meta(key).Name)
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

// Meta returns the backend secret name and type for an autocert cache key.
// Names are human-readable: <prefix>-<kind>-<domain-or-hash>.
func (c *Cache) Meta(key string) SecretMeta {
	switch Classify(key) {
	case KindAccount:
		return SecretMeta{Name: c.prefix + "-account-key", Type: SecretTypeOpaque}
	case KindCert:
		domain := key
		suffix := ""
		if strings.HasSuffix(domain, "+rsa") {
			domain = strings.TrimSuffix(domain, "+rsa")
			suffix = "-rsa"
		}
		return SecretMeta{Name: c.prefix + "-cert-" + sanitizeDomain(domain) + suffix, Type: SecretTypeCertificate}
	case KindALPN:
		domain := strings.TrimSuffix(key, "+token")
		return SecretMeta{Name: c.prefix + "-alpn-" + sanitizeDomain(domain), Type: SecretTypeCertificate}
	case KindHTTP01:
		token := strings.TrimSuffix(key, "+http-01")
		sum := sha256.Sum256([]byte(token))
		return SecretMeta{Name: c.prefix + "-http01-" + hex.EncodeToString(sum[:6]), Type: SecretTypeOpaque}
	default:
		sum := sha256.Sum256([]byte(key))
		return SecretMeta{Name: c.prefix + "-" + hex.EncodeToString(sum[:]), Type: SecretTypeOpaque}
	}
}

// Classify determines the Kind of an autocert cache key.
func Classify(key string) Kind {
	switch key {
	case "acme_account+key", "acme_account.key":
		return KindAccount
	}
	if strings.HasSuffix(key, "+http-01") {
		return KindHTTP01
	}
	if strings.HasSuffix(key, "+token") {
		return KindALPN
	}
	return KindCert
}

// sanitizeDomain converts a DNS name into a Scaleway-secret-safe name segment:
// lowercase, dots and other non-[a-z0-9-] characters replaced by "-",
// collapsed runs of "-" and trimmed of leading/trailing "-".
func sanitizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimRight(domain, "."))
	var b strings.Builder
	b.Grow(len(domain))
	prevDash := false
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
