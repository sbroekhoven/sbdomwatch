package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultURL is used when no API URL is configured.
const DefaultURL = "http://127.0.0.1:8480"

// Client is the CLI configuration. The token is not part of it: it comes
// from SBDOMWATCH_TOKEN only.
type Client struct {
	URL string `yaml:"url"`
}

// ClientConfigPath returns $XDG_CONFIG_HOME/sbdomwatch/config.yaml, falling
// back to ~/.config/sbdomwatch/config.yaml.
func ClientConfigPath(getenv func(string) string) string {
	dir := getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home := getenv("HOME")
		if home == "" {
			return ""
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "sbdomwatch", "config.yaml")
}

// LoadClient reads the client config at path; a missing file yields an
// empty config. Secret-looking and unknown keys are rejected.
func LoadClient(path string) (Client, error) {
	var c Client
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("read client config: %w", err)
	}
	if err := decodeStrict(data, &c); err != nil {
		return Client{}, fmt.Errorf("client config %s: %w", path, err)
	}
	return c, nil
}

// ResolveURL picks the API URL: flag, then environment, then config file,
// then DefaultURL.
func ResolveURL(flag string, getenv func(string) string, c Client) string {
	for _, v := range []string{flag, getenv(EnvURL), c.URL} {
		if v != "" {
			return v
		}
	}
	return DefaultURL
}
