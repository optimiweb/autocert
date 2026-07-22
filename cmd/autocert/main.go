package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/scaleway/scaleway-sdk-go/scw"

	"github.com/optimiweb/autocert/internal/app"
	"github.com/optimiweb/autocert/internal/config"
	"github.com/optimiweb/autocert/internal/scaleway"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	flag.Parse()

	level := new(slog.LevelVar)
	if rawLevel := os.Getenv("LOG_LEVEL"); rawLevel != "" {
		if err := level.UnmarshalText([]byte(rawLevel)); err != nil {
			fmt.Fprintf(os.Stderr, "invalid LOG_LEVEL %q: %v\n", rawLevel, err)
			os.Exit(2)
		}
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}
	if cfg.ACME.Email == "" {
		logger.Warn("acme.email is empty; Let's Encrypt recommends a contact email")
	}

	client, err := scw.NewClient(
		scw.WithAuth(cfg.Scaleway.AccessKey, cfg.Scaleway.SecretKey),
		scw.WithDefaultProjectID(cfg.Scaleway.ProjectID),
		scw.WithDefaultRegion(cfg.Scaleway.Region),
	)
	if err != nil {
		logger.Error("create Scaleway client", "error", err)
		os.Exit(1)
	}

	manager := app.NewManager(cfg, scaleway.NewCache(client, cfg))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.New(manager, logger).Run(ctx, cfg); err != nil {
		logger.Error("application failed", "error", err)
		os.Exit(1)
	}
}
