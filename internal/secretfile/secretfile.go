// Package secretfile reads a secret from a file on each use, with a very short
// cache, so credentials can be rotated without restarting a gateway and never
// need to appear in environment variables or command lines.
package secretfile

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

// File is a secret stored in a file. The zero value is not usable; use New.
type File struct {
	path string
	ttl  time.Duration

	mu      sync.Mutex
	value   string
	fetched time.Time
}

// New returns a File that re-reads path at most once per second.
func New(path string) *File { return &File{path: path, ttl: time.Second} }

// Get returns the trimmed contents of the file. An empty file is an error.
func (f *File) Get() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.value != "" && time.Since(f.fetched) < f.ttl {
		return f.value, nil
	}
	b, err := os.ReadFile(f.path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("secret file is empty")
	}
	f.value, f.fetched = v, time.Now()
	return v, nil
}
