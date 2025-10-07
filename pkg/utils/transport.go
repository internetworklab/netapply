package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/x509"
)

// FetchHTTPConfig fetches configuration from an HTTP(S) endpoint
func FetchHTTPConfigReadCloser(url string, tlsConfig *tls.Config, username, password string) (io.ReadCloser, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	request.Header.Set("Accept", "application/yaml")

	// Add basic authentication if credentials are provided
	if username != "" && password != "" {
		request.SetBasicAuth(username, password)
	}

	// Make HTTP request
	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	return resp.Body, nil
}

// FetchHTTPConfig fetches configuration from an HTTP(S) endpoint
func FetchHTTPConfig(url string, tlsConfig *tls.Config, username, password string) (io.Reader, error) {

	body, err := FetchHTTPConfigReadCloser(url, tlsConfig, username, password)
	if err != nil {
		return nil, err
	}

	defer body.Close()

	// Read response body into memory
	bodyContent, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return strings.NewReader(string(bodyContent)), nil
}

// GetTLSConfig creates a TLS configuration from the provided certificate files
func GetTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	// If no TLS parameters are provided, return nil (use default TLS config)
	if caCertPath == "" && clientCertPath == "" && clientKeyPath == "" {
		return nil, nil
	}

	config := &tls.Config{}

	// Load CA certificate if provided
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from '%s': %w", caCertPath, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from '%s'", caCertPath)
		}
		config.RootCAs = caCertPool
	}

	// Load client certificate and key if both are provided
	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate pair (cert: '%s', key: '%s'): %w", clientCertPath, clientKeyPath, err)
		}
		config.Certificates = []tls.Certificate{cert}
	} else if clientCertPath != "" || clientKeyPath != "" {
		// If only one of client cert or key is provided, that's an error
		return nil, fmt.Errorf("both client certificate and key must be provided together")
	}

	return config, nil
}
