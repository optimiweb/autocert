package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/scaleway/scaleway-sdk-go/scw"
	"golang.org/x/crypto/acme"
	"gopkg.in/yaml.v2"
)

const defaultSecretPrefix = "autocert"

type config struct {
	Domains     []string       `yaml:"domains"`
	HTTPAddress string         `yaml:"http_address"`
	ACME        acmeConfig     `yaml:"acme"`
	Scaleway    scalewayConfig `yaml:"scaleway"`
}

type acmeConfig struct {
	Email        string `yaml:"email"`
	DirectoryURL string `yaml:"directory_url"`
}

type scalewayConfig struct {
	AccessKey    string     `yaml:"access_key"`
	SecretKey    string     `yaml:"secret_key"`
	ProjectID    string     `yaml:"project_id"`
	Region       scw.Region `yaml:"region"`
	KeyID        string     `yaml:"key_id"`
	SecretPrefix string     `yaml:"secret_prefix"`
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read configuration %q: %w", path, err)
	}
	var cfg config
	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	expandConfigEnvironment(&cfg)

	if len(cfg.Domains) == 0 {
		return config{}, fmt.Errorf("domains must contain at least one domain")
	}
	for i, domain := range cfg.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if strings.HasPrefix(domain, "*.") {
			return config{}, fmt.Errorf("domains contains wildcard %q; HTTP-01 cannot validate wildcard domains", domain)
		}
		if domain == "" {
			return config{}, fmt.Errorf("domains contains an empty domain")
		}
		cfg.Domains[i] = domain
	}

	if err := requireConfigValue("scaleway.access_key", cfg.Scaleway.AccessKey); err != nil {
		return config{}, err
	}
	if err := requireConfigValue("scaleway.secret_key", cfg.Scaleway.SecretKey); err != nil {
		return config{}, err
	}
	if err := requireConfigValue("scaleway.project_id", cfg.Scaleway.ProjectID); err != nil {
		return config{}, err
	}

	if cfg.HTTPAddress == "" {
		cfg.HTTPAddress = ":80"
	}
	if cfg.ACME.DirectoryURL == "" {
		cfg.ACME.DirectoryURL = acme.LetsEncryptURL
	}
	if cfg.Scaleway.Region == "" {
		cfg.Scaleway.Region = "fr-par"
	}
	region, err := scw.ParseRegion(string(cfg.Scaleway.Region))
	if err != nil {
		return config{}, fmt.Errorf("scaleway.region: %w", err)
	}
	cfg.Scaleway.Region = region
	if cfg.Scaleway.SecretPrefix == "" {
		cfg.Scaleway.SecretPrefix = defaultSecretPrefix
	}
	return cfg, nil
}

func expandConfigEnvironment(config *config) {
	for i, domain := range config.Domains {
		config.Domains[i] = os.ExpandEnv(domain)
	}
	config.HTTPAddress = os.ExpandEnv(config.HTTPAddress)
	config.ACME.Email = os.ExpandEnv(config.ACME.Email)
	config.ACME.DirectoryURL = os.ExpandEnv(config.ACME.DirectoryURL)
	config.Scaleway.AccessKey = os.ExpandEnv(config.Scaleway.AccessKey)
	config.Scaleway.SecretKey = os.ExpandEnv(config.Scaleway.SecretKey)
	config.Scaleway.ProjectID = os.ExpandEnv(config.Scaleway.ProjectID)
	config.Scaleway.Region = scw.Region(os.ExpandEnv(string(config.Scaleway.Region)))
	config.Scaleway.KeyID = os.ExpandEnv(config.Scaleway.KeyID)
	config.Scaleway.SecretPrefix = os.ExpandEnv(config.Scaleway.SecretPrefix)
}

func requireConfigValue(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must be set", name)
	}
	return nil
}
