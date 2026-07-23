package fastly

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const cacheEntry = "-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBwgJ\n-----END CERTIFICATE-----\n"

func TestParseCertificate(t *testing.T) {
	certificate, err := ParseCertificate([]byte(cacheEntry))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(certificate.PrivateKey), "EC PRIVATE KEY") {
		t.Fatalf("private key = %q", certificate.PrivateKey)
	}
	if count := strings.Count(string(certificate.Chain), "BEGIN CERTIFICATE"); count != 2 {
		t.Fatalf("certificate count = %d, want 2", count)
	}
}

func TestParseCertificateRejectsInvalidEntries(t *testing.T) {
	for _, data := range []string{
		"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
		"-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\ninvalid",
		"-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\n",
	} {
		if _, err := ParseCertificate([]byte(data)); err == nil {
			t.Fatalf("ParseCertificate(%q) succeeded", data)
		}
	}
}

func TestUpload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/tls/certificates" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if token := r.Header.Get("Fastly-Key"); token != "token" {
			t.Fatalf("Fastly-Key = %q", token)
		}
		var body struct {
			CertBlob string `json:"cert_blob"`
			Key      string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body.CertBlob, "CERTIFICATE") || !strings.Contains(body.Key, "PRIVATE KEY") {
			t.Fatalf("unexpected body: %+v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"certificate-id"}`))
	}))
	defer server.Close()

	cert, err := ParseCertificate([]byte(cacheEntry))
	if err != nil {
		t.Fatal(err)
	}
	response, err := (Client{APIURL: server.URL + "/tls/certificates"}).Upload(context.Background(), "token", cert)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != `{"id":"certificate-id"}` {
		t.Fatalf("response = %q", response)
	}
}
