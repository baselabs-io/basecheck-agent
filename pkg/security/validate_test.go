package security

import (
	"testing"
)

func TestValidateHTTPS(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		allowHTTP bool
		wantErr   bool
	}{
		{
			name:      "HTTPS allowed",
			url:       "https://example.com",
			allowHTTP: false,
			wantErr:   false,
		},
		{
			name:      "HTTP blocked",
			url:       "http://example.com",
			allowHTTP: false,
			wantErr:   true,
		},
		{
			name:      "HTTP allowed when permitted",
			url:       "http://example.com",
			allowHTTP: true,
			wantErr:   false,
		},
		{
			name:      "HTTP with whitespace blocked",
			url:       "  http://example.com",
			allowHTTP: false,
			wantErr:   true,
		},
		{
			name:      "empty URL allowed",
			url:       "",
			allowHTTP: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHTTPS(tt.url, tt.allowHTTP)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHTTPS() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != ErrInsecureHTTP {
				t.Errorf("ValidateHTTPS() error = %v, want ErrInsecureHTTP", err)
			}
		})
	}
}
