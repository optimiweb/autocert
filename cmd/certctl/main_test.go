package main

import "testing"

func TestConfiguredDomain(t *testing.T) {
	domain, err := configuredDomain([]string{"example.com", "xn--bcher-kva.example"}, " BÜCHER.example. ")
	if err != nil {
		t.Fatal(err)
	}
	if domain != "xn--bcher-kva.example" {
		t.Fatalf("domain = %q", domain)
	}
}

func TestConfiguredDomainRejectsUnknownDomain(t *testing.T) {
	if _, err := configuredDomain([]string{"example.com"}, "other.example.com"); err == nil {
		t.Fatal("configuredDomain succeeded")
	}
}
