package app

import (
	"testing"
	"time"
)

func TestNextIssuanceRetryDelay(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "doubles", in: issuanceRetryMin, want: time.Minute},
		{name: "caps", in: issuanceRetryMax / 2, want: issuanceRetryMax},
		{name: "remains capped", in: issuanceRetryMax, want: issuanceRetryMax},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := nextIssuanceRetryDelay(test.in); got != test.want {
				t.Fatalf("nextIssuanceRetryDelay(%s) = %s, want %s", test.in, got, test.want)
			}
		})
	}
}
