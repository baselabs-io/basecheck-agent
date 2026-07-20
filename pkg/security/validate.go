package security

import (
	"errors"
	"strings"
)

// ErrInsecureHTTP is returned when an HTTP URL is used without explicit permission.
var ErrInsecureHTTP = errors.New("insecure HTTP connection not allowed; use HTTPS or set security.allow_http: true")

// ValidateHTTPS checks if the URL uses HTTPS. Returns ErrInsecureHTTP if
// the URL uses HTTP and allowHTTP is false.
func ValidateHTTPS(url string, allowHTTP bool) error {
	if !allowHTTP && strings.HasPrefix(strings.TrimSpace(url), "http://") {
		return ErrInsecureHTTP
	}
	return nil
}
