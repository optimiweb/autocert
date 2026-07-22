package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/scaleway/scaleway-sdk-go/scw"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

const (
	DefaultSecretPrefix = "autocert"
	DefaultHTTPAddress  = ":80"
	DefaultRegion       = "fr-par"
	DefaultSecretPath   = "/autocert"
)

type Config struct {
	Domains     []string       `yaml:"domains"`
	HTTPAddress string         `yaml:"http_address"`
	ACME        ACMEConfig     `yaml:"acme"`
	Scaleway    ScalewayConfig `yaml:"scaleway"`
}

type ACMEConfig struct {
	Email        string `yaml:"email"`
	DirectoryURL string `yaml:"directory_url"`
}

type ScalewayConfig struct {
	AccessKey    string     `yaml:"access_key"`
	SecretKey    string     `yaml:"secret_key"`
	ProjectID    string     `yaml:"project_id"`
	Region       scw.Region `yaml:"region"`
	KeyID        string     `yaml:"key_id"`
	SecretPrefix string     `yaml:"secret_prefix"`
	SecretPath   string     `yaml:"secret_path"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration %q: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	expandEnvironment(&cfg)
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func expandEnvironment(cfg *Config) {
	for i, domain := range cfg.Domains {
		cfg.Domains[i] = os.ExpandEnv(domain)
	}
	cfg.HTTPAddress = os.ExpandEnv(cfg.HTTPAddress)
	cfg.ACME.Email = os.ExpandEnv(cfg.ACME.Email)
	cfg.ACME.DirectoryURL = os.ExpandEnv(cfg.ACME.DirectoryURL)
	cfg.Scaleway.AccessKey = os.ExpandEnv(cfg.Scaleway.AccessKey)
	cfg.Scaleway.SecretKey = os.ExpandEnv(cfg.Scaleway.SecretKey)
	cfg.Scaleway.ProjectID = os.ExpandEnv(cfg.Scaleway.ProjectID)
	cfg.Scaleway.Region = scw.Region(os.ExpandEnv(string(cfg.Scaleway.Region)))
	cfg.Scaleway.KeyID = os.ExpandEnv(cfg.Scaleway.KeyID)
	cfg.Scaleway.SecretPrefix = os.ExpandEnv(cfg.Scaleway.SecretPrefix)
	cfg.Scaleway.SecretPath = os.ExpandEnv(cfg.Scaleway.SecretPath)
}

func validate(cfg *Config) error {
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("domains must contain at least one domain")
	}
	seen := make(map[string]struct{}, len(cfg.Domains))
	for i, domain := range cfg.Domains {
		domain = strings.TrimRight(strings.TrimSpace(domain), ".")
		if domain == "" {
			return fmt.Errorf("domains contains an empty domain")
		}
		if strings.HasPrefix(domain, "*.") {
			return fmt.Errorf("domains contains wildcard %q; HTTP-01 cannot validate wildcard domains", domain)
		}
		if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/:\\") {
			return fmt.Errorf("domains contains invalid domain %q", domain)
		}
		if !strings.Contains(strings.Trim(domain, "."), ".") {
			return fmt.Errorf("domains contains invalid domain %q", domain)
		}
		asciiDomain, err := idna.Lookup.ToASCII(domain)
		if err != nil {
			return fmt.Errorf("domains contains invalid domain %q: %w", domain, err)
		}
		domain = strings.ToLower(asciiDomain)
		if _, ok := seen[domain]; ok {
			return fmt.Errorf("domains contains duplicate domain %q", domain)
		}
		seen[domain] = struct{}{}
		cfg.Domains[i] = domain
	}

	if err := require("scaleway.access_key", cfg.Scaleway.AccessKey); err != nil {
		return err
	}
	if err := require("scaleway.secret_key", cfg.Scaleway.SecretKey); err != nil {
		return err
	}
	if err := require("scaleway.project_id", cfg.Scaleway.ProjectID); err != nil {
		return err
	}

	if cfg.HTTPAddress == "" {
		cfg.HTTPAddress = DefaultHTTPAddress
	}
	if err := validateHTTPAddress(cfg.HTTPAddress); err != nil {
		return err
	}

	if cfg.ACME.DirectoryURL == "" {
		cfg.ACME.DirectoryURL = acme.LetsEncryptURL
	}
	if err := validateDirectoryURL(cfg.ACME.DirectoryURL); err != nil {
		return err
	}

	if cfg.Scaleway.Region == "" {
		cfg.Scaleway.Region = DefaultRegion
	}
	region, err := scw.ParseRegion(string(cfg.Scaleway.Region))
	if err != nil {
		return fmt.Errorf("scaleway.region: %w", err)
	}
	cfg.Scaleway.Region = region

	if cfg.Scaleway.SecretPrefix == "" {
		cfg.Scaleway.SecretPrefix = DefaultSecretPrefix
	}
	if err := validateSecretPrefix(cfg.Scaleway.SecretPrefix); err != nil {
		return err
	}
	if cfg.Scaleway.SecretPath == "" {
		cfg.Scaleway.SecretPath = DefaultSecretPath
	}
	if err := validateSecretPath(cfg.Scaleway.SecretPath); err != nil {
		return err
	}
	return nil
}

func validateHTTPAddress(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("http_address: %w", err)
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber > 65535 {
		return fmt.Errorf("http_address must include a port between 0 and 65535")
	}
	return nil
}

func require(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must be set", name)
	}
	return nil
}

func validateDirectoryURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("acme.directory_url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("acme.directory_url must be an http(s) URL")
	}
	if parsed.Host == "" {
		return fmt.Errorf("acme.directory_url must include a host")
	}
	return nil
}

func validateSecretPrefix(prefix string) error {
	if len(prefix) == 0 || len(prefix) > 50 {
		return fmt.Errorf("scaleway.secret_prefix must be between 1 and 50 characters")
	}
	for _, r := range prefix {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("scaleway.secret_prefix contains invalid character %q", string(r))
	}
	return nil
}

func validateSecretPath(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("scaleway.secret_path must start with '/'")
	}
	if path != "/" && strings.HasSuffix(path, "/") {
		return fmt.Errorf("scaleway.secret_path must not end with '/'")
	}
	if strings.Contains(path, "//") {
		return fmt.Errorf("scaleway.secret_path must not contain empty segments")
	}
	return nil
}
