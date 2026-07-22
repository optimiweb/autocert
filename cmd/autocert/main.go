package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/scaleway/scaleway-sdk-go/scw"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	flag.Parse()
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	client, err := scw.NewClient(
		scw.WithAuth(config.Scaleway.AccessKey, config.Scaleway.SecretKey),
		scw.WithDefaultProjectID(config.Scaleway.ProjectID),
		scw.WithDefaultRegion(config.Scaleway.Region),
	)
	if err != nil {
		log.Fatalf("create Scaleway client: %v", err)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      newSecretManagerCache(client, config),
		HostPolicy: autocert.HostWhitelist(config.Domains...),
		Email:      config.ACME.Email,
		Client:     &acme.Client{DirectoryURL: config.ACME.DirectoryURL},
	}
	server := &http.Server{
		Addr:              config.HTTPAddress,
		Handler:           manager.HTTPHandler(applicationHandler()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	listener, err := net.Listen("tcp", config.HTTPAddress)
	if err != nil {
		log.Fatalf("listen for ACME HTTP-01 challenges on %s: %v", config.HTTPAddress, err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("serving ACME HTTP-01 challenges on %s", config.HTTPAddress)
		errCh <- server.Serve(listener)
	}()

	// Request certificates after the HTTP listener is accepting ACME validations.
	for _, domain := range config.Domains {
		if _, err := manager.GetCertificate(&tls.ClientHelloInfo{
			ServerName:      domain,
			SupportedProtos: []string{"http/1.1"},
		}); err != nil {
			shutdown(server)
			log.Fatalf("obtain certificate for %q: %v", domain, err)
		}
		log.Printf("certificate ready for %s", domain)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case signal := <-stop:
		log.Printf("received %s, shutting down", signal)
		shutdown(server)
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

func applicationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
}

func shutdown(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("shutdown HTTP server: %v", err)
	}
}
