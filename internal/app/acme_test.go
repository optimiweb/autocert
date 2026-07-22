package app_test

import (
	"context"
	"testing"

	"github.com/optimiweb/autocert/internal/app"
	"github.com/optimiweb/autocert/internal/config"
)

func TestNewManager(t *testing.T) {
	cache := &memoryCache{}
	manager := app.NewManager(config.Config{
		Domains: []string{"example.com"},
		ACME: config.ACMEConfig{
			Email:        "ops@example.com",
			DirectoryURL: "https://acme.example.test/directory",
		},
	}, cache)

	if manager.Email != "ops@example.com" {
		t.Fatalf("email = %q", manager.Email)
	}
	if manager.Client.DirectoryURL != "https://acme.example.test/directory" {
		t.Fatalf("directory URL = %q", manager.Client.DirectoryURL)
	}
	if manager.Cache != cache {
		t.Fatal("cache was not configured")
	}
	if err := manager.HostPolicy(context.Background(), "example.com"); err != nil {
		t.Fatalf("host policy rejected configured domain: %v", err)
	}
}

type memoryCache struct{}

func (memoryCache) Get(context.Context, string) ([]byte, error) { return nil, nil }
func (memoryCache) Put(context.Context, string, []byte) error   { return nil }
func (memoryCache) Delete(context.Context, string) error        { return nil }
