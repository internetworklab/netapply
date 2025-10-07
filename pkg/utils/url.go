package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strings"
)

// A object of struct type URLReader is an implementation of io.ReadCloser,
// it is the responsibility of the caller to close the reader
type URLReader struct {
	url     string
	reader  io.ReadCloser
	isStdin bool
}

type URLReaderTransportOptions struct {
	TLSConfig *tls.Config
	Username  string
	Password  string
}

const FilePathPresumedToBeStdin = "-"
const FilePathThatIsStdin = "/dev/stdin"

func NewURLReader(url string, options *URLReaderTransportOptions) (io.ReadCloser, error) {
	url = strings.TrimSpace(url)

	if url == FilePathPresumedToBeStdin || url == FilePathThatIsStdin {
		return &URLReader{
			url:     url,
			reader:  os.Stdin,
			isStdin: true,
		}, nil
	}

	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		return FetchHTTPConfigReadCloser(url, options.TLSConfig, options.Username, options.Password)
	}

	f, err := os.Open(url)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	return f, nil
}

func (reader *URLReader) Read(p []byte) (n int, err error) {
	return reader.reader.Read(p)
}

func (reader *URLReader) Close() error {
	if reader.isStdin {
		return nil
	}
	return reader.reader.Close()
}
