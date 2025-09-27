package utils

import (
	"os"
	"path/filepath"
	"strings"
)

func ResolvePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}

	wd, err := os.Getwd()
	if err != nil {
		return path
	}

	return filepath.Join(wd, path)
}
