package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	secret "github.com/scaleway/scaleway-sdk-go/api/secret/v1beta1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"golang.org/x/crypto/acme/autocert"
)

const maxSecretVersionSize = 64 * 1024

type secretStore interface {
	find(context.Context, string) (string, error)
	read(context.Context, string) ([]byte, error)
	create(context.Context, string) (string, error)
	write(context.Context, string, []byte) error
	disableLatest(context.Context, string) error
}

type secretManagerCache struct {
	store  secretStore
	prefix string
	mu     sync.Mutex
}

func newSecretManagerCache(client *scw.Client, config config) *secretManagerCache {
	return &secretManagerCache{
		store: &scalewaySecretStore{
			api:       secret.NewAPI(client),
			projectID: config.Scaleway.ProjectID,
			region:    config.Scaleway.Region,
			keyID:     config.Scaleway.KeyID,
		},
		prefix: config.Scaleway.SecretPrefix,
	}
}

func (c *secretManagerCache) Get(ctx context.Context, key string) ([]byte, error) {
	id, err := c.store.find(ctx, c.secretName(key))
	if errors.Is(err, autocert.ErrCacheMiss) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("find secret for cache key %q: %w", key, err)
	}
	data, err := c.store.read(ctx, id)
	if errors.Is(err, autocert.ErrCacheMiss) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("read secret for cache key %q: %w", key, err)
	}
	return data, nil
}

func (c *secretManagerCache) Put(ctx context.Context, key string, data []byte) error {
	if len(data) > maxSecretVersionSize {
		return fmt.Errorf("cache data for %q exceeds Secret Manager's 64 KiB version limit", key)
	}

	// Avoid duplicate secret creation and version interleaving in this process.
	c.mu.Lock()
	defer c.mu.Unlock()
	name := c.secretName(key)
	id, err := c.store.find(ctx, name)
	if errors.Is(err, autocert.ErrCacheMiss) {
		id, err = c.store.create(ctx, name)
	}
	if err != nil {
		return fmt.Errorf("prepare secret for cache key %q: %w", key, err)
	}
	if err := c.store.write(ctx, id, data); err != nil {
		return fmt.Errorf("write secret for cache key %q: %w", key, err)
	}
	return nil
}

func (c *secretManagerCache) Delete(ctx context.Context, key string) error {
	id, err := c.store.find(ctx, c.secretName(key))
	if errors.Is(err, autocert.ErrCacheMiss) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find secret for cache key %q: %w", key, err)
	}
	if err := c.store.disableLatest(ctx, id); err != nil {
		return fmt.Errorf("disable secret for cache key %q: %w", key, err)
	}
	return nil
}

func (c *secretManagerCache) secretName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return c.prefix + "-" + hex.EncodeToString(sum[:])
}

type scalewaySecretStore struct {
	api       *secret.API
	projectID string
	region    scw.Region
	keyID     string
}

func (s *scalewaySecretStore) find(ctx context.Context, name string) (string, error) {
	projectID := s.projectID
	pageSize := uint32(2)
	secrets, err := s.api.ListSecrets(&secret.ListSecretsRequest{
		Region:    s.region,
		ProjectID: &projectID,
		Name:      &name,
		PageSize:  &pageSize,
	}, scw.WithContext(ctx))
	if err != nil {
		return "", err
	}
	for _, item := range secrets.Secrets {
		if item.Name == name {
			return item.ID, nil
		}
	}
	return "", autocert.ErrCacheMiss
}

func (s *scalewaySecretStore) read(ctx context.Context, id string) ([]byte, error) {
	version, err := s.api.AccessSecretVersion(&secret.AccessSecretVersionRequest{
		Region:   s.region,
		SecretID: id,
		Revision: "latest_enabled",
	}, scw.WithContext(ctx))
	if isNotFound(err) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	return version.Data, nil
}

func (s *scalewaySecretStore) create(ctx context.Context, name string) (string, error) {
	request := &secret.CreateSecretRequest{
		Region:    s.region,
		ProjectID: s.projectID,
		Name:      name,
		Tags:      []string{"autocert"},
	}
	if s.keyID != "" {
		request.KeyID = &s.keyID
	}
	created, err := s.api.CreateSecret(request, scw.WithContext(ctx))
	if err == nil {
		return created.ID, nil
	}
	if id, findErr := s.find(ctx, name); findErr == nil {
		return id, nil
	}
	return "", err
}

func (s *scalewaySecretStore) write(ctx context.Context, id string, data []byte) error {
	disablePrevious := true
	_, err := s.api.CreateSecretVersion(&secret.CreateSecretVersionRequest{
		Region:          s.region,
		SecretID:        id,
		Data:            data,
		DisablePrevious: &disablePrevious,
	}, scw.WithContext(ctx))
	return err
}

func (s *scalewaySecretStore) disableLatest(ctx context.Context, id string) error {
	_, err := s.api.DisableSecretVersion(&secret.DisableSecretVersionRequest{
		Region:   s.region,
		SecretID: id,
		Revision: "latest_enabled",
	}, scw.WithContext(ctx))
	if isNotFound(err) {
		return nil
	}
	return err
}

func isNotFound(err error) bool {
	var responseErr *scw.ResponseError
	return errors.As(err, &responseErr) && responseErr.StatusCode == 404
}
