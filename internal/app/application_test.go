package app_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/optimiweb/autocert/internal/app"
	"github.com/optimiweb/autocert/internal/config"
)

func TestHandler(t *testing.T) {
	handler := app.Handler()

	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, healthRequest)
	if healthResponse.Code != http.StatusNoContent {
		t.Fatalf("health status = %d, want %d", healthResponse.Code, http.StatusNoContent)
	}

	missingRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingRequest)
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want %d", missingResponse.Code, http.StatusNotFound)
	}
}

func TestRunObtainsCertificateAndShutsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager := &fakeCertificateManager{requests: make(chan *tls.ClientHelloInfo, 2)}
	application := app.New(manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	application.SetListen(func(_, _ string) (net.Listener, error) { return listener, nil })

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- application.Run(ctx, config.Config{
			Domains:     []string{"example.com", "www.example.com"},
			HTTPAddress: listener.Addr().String(),
		})
	}()

	for i := 0; i < 2; i++ {
		select {
		case req := <-manager.requests:
			if req.ServerName != "example.com" && req.ServerName != "www.example.com" {
				t.Fatalf("unexpected domain %q", req.ServerName)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for certificate request")
		}
	}

	response, err := (&http.Client{Timeout: time.Second}).Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("health status = %d", response.StatusCode)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("application did not shut down")
	}
}

func TestRunRetriesIssuanceFailuresUntilCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager := &fakeCertificateManager{
		requests: make(chan *tls.ClientHelloInfo, 2),
		err:      errors.New("issue failed"),
	}
	application := app.New(manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	application.SetListen(func(_, _ string) (net.Listener, error) { return listener, nil })

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- application.Run(ctx, config.Config{
			Domains:     []string{"a.example.com", "b.example.com"},
			HTTPAddress: listener.Addr().String(),
		})
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-manager.requests:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for certificate request")
		}
	}
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("application did not shut down")
	}
}

type fakeCertificateManager struct {
	requests chan *tls.ClientHelloInfo
	err      error
}

func (m *fakeCertificateManager) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}

func (m *fakeCertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.requests <- hello
	return nil, m.err
}
