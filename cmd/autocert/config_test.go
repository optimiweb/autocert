package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestLoadConfig(t *testing.T) {
	config, err := loadTestConfig(t, `
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
	if strings.Join(config.Domains, ",") != "example.com,www.example.com" {
		t.Fatalf("domains = %v", config.Domains)
	}
	if config.ACME.DirectoryURL != acme.LetsEncryptURL {
		t.Fatalf("directory URL = %q", config.ACME.DirectoryURL)
	}
	if config.HTTPAddress != ":80" {
		t.Fatalf("HTTP address = %q", config.HTTPAddress)
	}
}

func TestLoadConfigRejectsWildcardDomain(t *testing.T) {
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

func TestLoadConfigRejectsUnknownField(t *testing.T) {
	_, err := loadTestConfig(t, `
domains: [example.com]
unknown: value
scaleway:
  access_key: access
  secret_key: secret
  project_id: project
`)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("error = %v, want unknown field error", err)
	}
}

func TestLoadConfigExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("TEST_SCW_ACCESS_KEY", "access")
	t.Setenv("TEST_SCW_SECRET_KEY", "secret")
	config, err := loadTestConfig(t, `
domains: [example.com]
scaleway:
  access_key: ${TEST_SCW_ACCESS_KEY}
  secret_key: ${TEST_SCW_SECRET_KEY}
  project_id: project
`)
	if err != nil {
		t.Fatal(err)
	}
	if config.Scaleway.AccessKey != "access" || config.Scaleway.SecretKey != "secret" {
		t.Fatalf("credentials were not expanded: %+v", config.Scaleway)
	}
}

func loadTestConfig(t *testing.T, contents string) (config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadConfig(path)
}
