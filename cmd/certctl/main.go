// certctl imports issued certificates into external TLS providers.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/scaleway/scaleway-sdk-go/scw"
	"golang.org/x/net/idna"

	"github.com/optimiweb/autocert/internal/config"
	"github.com/optimiweb/autocert/internal/fastly"
	"github.com/optimiweb/autocert/internal/scaleway"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	domain := flag.String("domain", "", "configured domain whose ECDSA certificate will be imported")
	fastlyToken := flag.String("fastly-api-token", os.Getenv("FASTLY_API_TOKEN"), "Fastly API token (defaults to FASTLY_API_TOKEN)")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "-domain is required")
		os.Exit(2)
	}
	if *fastlyToken == "" {
		fmt.Fprintln(os.Stderr, "-fastly-api-token or FASTLY_API_TOKEN is required")
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fail("load configuration", err)
	}
	selectedDomain, err := configuredDomain(cfg.Domains, *domain)
	if err != nil {
		fail("select certificate", err)
	}
	client, err := scw.NewClient(
		scw.WithAuth(cfg.Scaleway.AccessKey, cfg.Scaleway.SecretKey),
		scw.WithDefaultProjectID(cfg.Scaleway.ProjectID),
		scw.WithDefaultRegion(cfg.Scaleway.Region),
	)
	if err != nil {
		fail("create Scaleway client", err)
	}

	data, err := scaleway.NewCache(client, cfg).Get(context.Background(), selectedDomain)
	if err != nil {
		fail("read certificate from Scaleway Secret Manager", err)
	}
	certificate, err := fastly.ParseCertificate(data)
	if err != nil {
		fail("parse certificate cache entry", err)
	}
	_, err = (fastly.Client{}).Upload(context.Background(), *fastlyToken, certificate)
	if err != nil {
		fail("import certificate into Fastly", err)
	}

	slog.Info("certificate imported into Fastly", "domain", selectedDomain)
}

func configuredDomain(domains []string, requested string) (string, error) {
	requested = strings.TrimRight(strings.ToLower(strings.TrimSpace(requested)), ".")
	var err error
	requested, err = idna.Lookup.ToASCII(requested)
	if err != nil {
		return "", fmt.Errorf("normalize domain: %w", err)
	}
	for _, domain := range domains {
		if domain == requested {
			return domain, nil
		}
	}
	return "", fmt.Errorf("domain %q is not configured for issuance", requested)
}

func fail(message string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", message, err)
	os.Exit(1)
}
