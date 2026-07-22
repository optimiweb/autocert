package app

import (
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/optimiweb/autocert/internal/config"
)

// NewManager builds an autocert.Manager for HTTP-01 issuance.
func NewManager(cfg config.Config, cache autocert.Cache) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.ACME.Email,
		Client:     &acme.Client{DirectoryURL: cfg.ACME.DirectoryURL},
	}
}
