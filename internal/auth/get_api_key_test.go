package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErr     string
	}{
		{
			name:        "valid API key",
			headerValue: "ApiKey my-secret-key",
			wantKey:     "my-secret-key",
		},
		{
			name:    "missing header",
			wantErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:        "wrong scheme",
			headerValue: "Bearer my-secret-key",
			wantErr:     "malformed authorization header",
		},
		{
			name:        "missing key",
			headerValue: "ApiKey",
			wantErr:     "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerValue != "" {
				headers.Set("Authorization", tt.headerValue)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected an error, got nil")
			}

			if tt.wantErr == ErrNoAuthHeaderIncluded.Error() {
				if !errors.Is(err, ErrNoAuthHeaderIncluded) {
					t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
				}
			} else if err.Error() != tt.wantErr {
				t.Fatalf("expected %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}