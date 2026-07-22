package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/optimiweb/autocert/internal/config"
)

const (
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	issuanceRetryMin  = 30 * time.Second
	issuanceRetryMax  = 5 * time.Minute
	renewalCheckEvery = 12 * time.Hour
)

// CertificateManager is the subset of autocert.Manager used by Application.
type CertificateManager interface {
	HTTPHandler(http.Handler) http.Handler
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Application serves HTTP-01 challenges and obtains certificates at startup.
type Application struct {
	manager CertificateManager
	listen  func(network, address string) (net.Listener, error)
	logger  *slog.Logger
}

func New(manager CertificateManager, logger *slog.Logger) *Application {
	if logger == nil {
		logger = slog.Default()
	}
	return &Application{
		manager: manager,
		listen:  net.Listen,
		logger:  logger,
	}
}

// SetListen replaces the listen function. Intended for tests.
func (a *Application) SetListen(fn func(network, address string) (net.Listener, error)) {
	a.listen = fn
}

// Run listens for HTTP-01 challenges, obtains certificates for configured domains,
// then blocks until ctx is canceled or the HTTP server fails.
func (a *Application) Run(ctx context.Context, cfg config.Config) error {
	listener, err := a.listen("tcp", cfg.HTTPAddress)
	if err != nil {
		return fmt.Errorf("listen for ACME HTTP-01 challenges on %s: %w", cfg.HTTPAddress, err)
	}
	server := &http.Server{
		Addr:              cfg.HTTPAddress,
		Handler:           a.manager.HTTPHandler(Handler()),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 1)
	go func() {
		a.logger.Info("serving ACME HTTP-01 challenges", "address", cfg.HTTPAddress)
		errCh <- server.Serve(listener)
	}()

	if err := a.obtainCertificatesUntilReady(ctx, cfg.Domains, errCh); err != nil {
		shutdownErr := shutdownServer(server)
		if ctx.Err() != nil {
			return shutdownErr
		}
		return errors.Join(err, shutdownErr)
	}
	renewalTicker := time.NewTicker(renewalCheckEvery)
	defer renewalTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("shutting down")
			if err := shutdownServer(server); err != nil {
				return err
			}
			// Drain serve result after graceful shutdown.
			select {
			case err := <-errCh:
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					return fmt.Errorf("serve ACME HTTP-01 challenges: %w", err)
				}
			default:
			}
			return nil
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return fmt.Errorf("serve ACME HTTP-01 challenges: %w", err)
		case <-renewalTicker.C:
			if err := a.obtainCertificates(ctx, cfg.Domains); err != nil {
				a.logger.Error("certificate renewal check failed", "error", err)
			}
		}
	}
}

func (a *Application) obtainCertificatesUntilReady(ctx context.Context, domains []string, serverErrors <-chan error) error {
	delay := issuanceRetryMin
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case err := <-serverErrors:
			return fmt.Errorf("serve ACME HTTP-01 challenges: %w", err)
		default:
		}

		if err := a.obtainCertificates(ctx, domains); err == nil {
			return nil
		} else {
			a.logger.Error("certificate issuance failed; retrying", "error", err, "retry_after", delay)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case err := <-serverErrors:
			timer.Stop()
			return fmt.Errorf("serve ACME HTTP-01 challenges: %w", err)
		case <-timer.C:
			delay = nextIssuanceRetryDelay(delay)
		}
	}
}

func nextIssuanceRetryDelay(delay time.Duration) time.Duration {
	if delay >= issuanceRetryMax/2 {
		return issuanceRetryMax
	}
	return delay * 2
}

func (a *Application) obtainCertificates(ctx context.Context, domains []string) error {
	var errs []error
	for _, domain := range domains {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("obtain certificate for %q: %w", domain, err))
			break
		}
		a.logger.Info("requesting certificate", "domain", domain)
		// autocert accepts a ClientHelloInfo but creates its own five-minute
		// context internally; application shutdown cannot interrupt this call.
		if _, err := a.manager.GetCertificate(&tls.ClientHelloInfo{
			ServerName:      domain,
			SupportedProtos: []string{"http/1.1"},
		}); err != nil {
			errs = append(errs, fmt.Errorf("obtain certificate for %q: %w", domain, err))
			// Continue remaining domains so operators see the full failure set.
			continue
		}
		a.logger.Info("certificate ready", "domain", domain)
	}
	return errors.Join(errs...)
}

// Handler returns the non-ACME HTTP handler.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
}

func shutdownServer(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	return nil
}
