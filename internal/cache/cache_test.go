package cache_test

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/acme/autocert"

	"github.com/optimiweb/autocert/internal/cache"
)

func TestCacheRoundTrip(t *testing.T) {
	store := newMemoryStore()
	c := cache.New(store, "test")
	ctx := context.Background()
	if err := c.Put(ctx, "example.com", []byte("certificate")); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, "example.com")
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

func TestCacheDeleteMakesCacheMiss(t *testing.T) {
	store := newMemoryStore()
	c := cache.New(store, "test")
	ctx := context.Background()
	if err := c.Put(ctx, "example.com", []byte("certificate")); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	_, err := c.Get(ctx, "example.com")
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("error = %v, want cache miss", err)
	}
}

func TestCacheRejectsOversizedVersion(t *testing.T) {
	c := cache.New(newMemoryStore(), "test")
	err := c.Put(context.Background(), "example.com", make([]byte, cache.MaxSecretVersionSize+1))
	if err == nil {
		t.Fatal("Put succeeded for oversized data")
	}
}

func TestCacheGetMiss(t *testing.T) {
	c := cache.New(newMemoryStore(), "test")
	_, err := c.Get(context.Background(), "missing.example")
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("error = %v, want cache miss", err)
	}
}

type memoryStore struct {
	items map[string][]byte
	names map[string]string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{items: make(map[string][]byte), names: make(map[string]string)}
}

func (s *memoryStore) Find(_ context.Context, name string) (string, error) {
	id, ok := s.names[name]
	if !ok {
		return "", cache.ErrNotFound
	}
	return id, nil
}

func (s *memoryStore) Read(_ context.Context, id string) ([]byte, error) {
	data, ok := s.items[id]
	if !ok {
		return nil, cache.ErrNotFound
	}
	return append([]byte(nil), data...), nil
}

func (s *memoryStore) Create(_ context.Context, name string) (string, error) {
	id := name
	s.names[name] = id
	return id, nil
}

func (s *memoryStore) Write(_ context.Context, id string, data []byte) error {
	s.items[id] = append([]byte(nil), data...)
	return nil
}

func (s *memoryStore) DisableLatest(_ context.Context, id string) error {
	delete(s.items, id)
	return nil
}
