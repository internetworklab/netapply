package utils_test

import (
	"io"
	"strings"
	"testing"

	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func TestNewURLReaderWithHTTPSNoAuth(t *testing.T) {
	reader, err := pkgutils.NewURLReader("https://demofiles.imsb.me/demo/configs/test.yaml", &pkgutils.URLReaderTransportOptions{})
	if err != nil {
		t.Fatalf("failed to create URL reader: %v", err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read content: %v", err)
	}

	if len(content) == 0 {
		t.Fatalf("failed to read content: %v", err)
	}

	for i, l := range strings.Split(string(content), "\n") {
		t.Logf("content[%d]: %s", i, l)
	}
}

func TestNewURLReaderWithHTTPSBasicAuth(t *testing.T) {
	urlReaderConfig := &pkgutils.URLReaderTransportOptions{
		Username: "admin",
		Password: "123456",
	}
	reader, err := pkgutils.NewURLReader("https://demofiles.imsb.me/demo/wg/wg-lax1.key", urlReaderConfig)
	if err != nil {
		t.Fatalf("failed to create URL reader: %v", err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read content: %v", err)
	}

	if len(content) == 0 {
		t.Fatalf("failed to read content: %v", err)
	}

	for i, l := range strings.Split(string(content), "\n") {
		t.Logf("content[%d]: %s", i, l)
	}
}

func TestNewURLReaderWithHTTPSWrongBasicAuth(t *testing.T) {
	urlReaderConfig := &pkgutils.URLReaderTransportOptions{
		Username: "admin",
		Password: "1234567",
	}
	_, err := pkgutils.NewURLReader("https://demofiles.imsb.me/demo/wg/wg-lax1.key", urlReaderConfig)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
