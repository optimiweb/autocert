package main

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

func TestSecretManagerCacheRoundTrip(t *testing.T) {
	store := &memorySecretStore{items: make(map[string][]byte), names: make(map[string]string)}
	cache := &secretManagerCache{store: store, prefix: "test"}
	ctx := context.Background()
	if err := cache.Put(ctx, "example.com", []byte("certificate")); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "certificate" {
		t.Fatalf("data = %q", got)
	}
	if len(store.items) != 1 {
		t.Fatalf("stored secrets = %d, want 1", len(store.items))
	}
}

func TestSecretManagerCacheDeleteMakesCacheMiss(t *testing.T) {
	store := &memorySecretStore{items: make(map[string][]byte), names: make(map[string]string)}
	cache := &secretManagerCache{store: store, prefix: "test"}
	ctx := context.Background()
	if err := cache.Put(ctx, "example.com", []byte("certificate")); err != nil {
		t.Fatal(err)
	}
	if err := cache.Delete(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	_, err := cache.Get(ctx, "example.com")
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("error = %v, want cache miss", err)
	}
}

func TestSecretManagerCacheRejectsOversizedVersion(t *testing.T) {
	cache := &secretManagerCache{store: &memorySecretStore{items: make(map[string][]byte), names: make(map[string]string)}, prefix: "test"}
	err := cache.Put(context.Background(), "example.com", make([]byte, maxSecretVersionSize+1))
	if err == nil {
		t.Fatal("Put succeeded for oversized data")
	}
}

type memorySecretStore struct {
	items map[string][]byte
	names map[string]string
}

func (s *memorySecretStore) find(_ context.Context, name string) (string, error) {
	id, ok := s.names[name]
	if !ok {
		return "", autocert.ErrCacheMiss
	}
	return id, nil
}

func (s *memorySecretStore) read(_ context.Context, id string) ([]byte, error) {
	data, ok := s.items[id]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	return append([]byte(nil), data...), nil
}

func (s *memorySecretStore) create(_ context.Context, name string) (string, error) {
	id := name
	s.names[name] = id
	return id, nil
}

func (s *memorySecretStore) write(_ context.Context, id string, data []byte) error {
	s.items[id] = append([]byte(nil), data...)
	return nil
}

func (s *memorySecretStore) disableLatest(_ context.Context, id string) error {
	delete(s.items, id)
	return nil
}
