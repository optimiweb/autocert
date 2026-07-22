package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"

	"github.com/optimiweb/autocert/internal/config"
)

func TestLoad(t *testing.T) {
	cfg, err := loadTestConfig(t, `
domains:
  - Example.com
  - www.example.com
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.Domains, ",") != "example.com,www.example.com" {
		t.Fatalf("domains = %v", cfg.Domains)
	}
	if cfg.ACME.DirectoryURL != acme.LetsEncryptURL {
		t.Fatalf("directory URL = %q", cfg.ACME.DirectoryURL)
	}
	if cfg.HTTPAddress != ":80" {
		t.Fatalf("HTTP address = %q", cfg.HTTPAddress)
	}
	if cfg.Scaleway.SecretPath != "/autocert" {
		t.Fatalf("secret path = %q", cfg.Scaleway.SecretPath)
	}
}

func TestLoadRejectsWildcardDomain(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: ["*.example.com"]
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err == nil || !strings.Contains(err.Error(), "HTTP-01") {
		t.Fatalf("error = %v, want HTTP-01 wildcard error", err)
	}
}

func TestLoadRejectsDuplicateDomain(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: [example.com, Example.com]
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want duplicate domain error", err)
	}
}

func TestLoadNormalizesDomains(t *testing.T) {
	cfg, err := loadTestConfig(t, `
domains: [Example.com..., "b\u00fccher.example"]
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(cfg.Domains, ","), "example.com,xn--bcher-kva.example"; got != want {
		t.Fatalf("domains = %q, want %q", got, want)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: [example.com]
unknown: value
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadRejectsInvalidDirectoryURL(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: [example.com]
acme:
  directory_url: not-a-url
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err == nil || !strings.Contains(err.Error(), "directory_url") {
		t.Fatalf("error = %v, want directory_url error", err)
	}
}

func TestLoadRejectsInvalidHTTPAddress(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: [example.com]
http_address: example.com
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err == nil || !strings.Contains(err.Error(), "http_address") {
		t.Fatalf("error = %v, want http_address error", err)
	}
}

func TestLoadRejectsInvalidSecretPath(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: [example.com]
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
  secret_path: autocert
`)
	if err == nil || !strings.Contains(err.Error(), "secret_path") {
		t.Fatalf("error = %v, want secret_path error", err)
	}
}

func TestLoadRejectsInvalidScalewaySettings(t *testing.T) {
	for _, test := range []struct {
		name    string
		setting string
		want    string
	}{
		{name: "region", setting: "region: nowhere", want: "scaleway.region"},
		{name: "prefix", setting: "secret_prefix: invalid/prefix", want: "secret_prefix"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadTestConfig(t, `
domains: [example.com]
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
  `+test.setting)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("TEST_SCW_ACCESS_KEY", "access")
	t.Setenv("TEST_SCW_SECRET_KEY", "secret")
	cfg, err := loadTestConfig(t, `
domains: [example.com]
scaleway:
  access_key: ${TEST_SCW_ACCESS_KEY}
  secret_key: ${TEST_SCW_SECRET_KEY}
  project_id: project
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scaleway.AccessKey != "access" || cfg.Scaleway.SecretKey != "secret" {
		t.Fatalf("credentials were not expanded: %+v", cfg.Scaleway)
	}
}

func TestLoadRejectsUnsetDomainEnvironmentVariable(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: ["${UNSET_AUTOCERT_DOMAIN}"]
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err == nil || !strings.Contains(err.Error(), "empty domain") {
		t.Fatalf("error = %v, want empty domain error", err)
	}
}

func loadTestConfig(t *testing.T, contents string) (config.Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Load(path)
}
