// Package fastly implements the Fastly TLS Certificates API.
package fastly

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const certificatesURL = "https://api.fastly.com/tls/certificates"

// Certificate contains PEM material imported from an autocert cache entry.
type Certificate struct {
	PrivateKey []byte
	Chain      []byte
}

// ParseCertificate separates the private key and certificate chain from an
// autocert cache entry.
func ParseCertificate(data []byte) (Certificate, error) {
	privateKey, rest := pem.Decode(data)
	if privateKey == nil || !strings.Contains(privateKey.Type, "PRIVATE KEY") {
		return Certificate{}, fmt.Errorf("cache entry does not start with a PEM private key")
	}

	var chain bytes.Buffer
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return Certificate{}, fmt.Errorf("cache entry contains invalid PEM after private key")
		}
		if block.Type != "CERTIFICATE" {
			return Certificate{}, fmt.Errorf("cache entry contains PEM block %q after private key", block.Type)
		}
		if err := pem.Encode(&chain, block); err != nil {
			return Certificate{}, fmt.Errorf("encode certificate chain: %w", err)
		}
		rest = remaining
	}
	if chain.Len() == 0 {
		return Certificate{}, fmt.Errorf("cache entry has no certificate chain")
	}

	return Certificate{
		PrivateKey: pem.EncodeToMemory(privateKey),
		Chain:      chain.Bytes(),
	}, nil
}

// Client imports certificates into Fastly.
type Client struct {
	HTTPClient *http.Client
	APIURL     string
}

// Upload imports cert into Fastly and returns its response body.
func (c Client) Upload(ctx context.Context, token string, cert Certificate) ([]byte, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("Fastly API token is empty")
	}
	endpoint := c.APIURL
	if endpoint == "" {
		endpoint = certificatesURL
	}
	body, err := json.Marshal(struct {
		CertBlob string `json:"cert_blob"`
		Key      string `json:"key"`
	}{
		CertBlob: string(cert.Chain),
		Key:      string(cert.PrivateKey),
	})
	if err != nil {
		return nil, fmt.Errorf("encode Fastly certificate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create Fastly certificate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Fastly-Key", token)

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload certificate to Fastly: %w", err)
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read Fastly response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("upload certificate to Fastly: %s: %s", resp.Status, strings.TrimSpace(string(response)))
	}
	return response, nil
}
