package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ReadDotenv reads a .env file. A missing file is not an error and yields an
// empty map. Errors never include values, because .env files hold secrets.
func ReadDotenv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open env file %s: %w", path, err)
	}
	defer f.Close()
	vars, err := ParseDotenv(f)
	if err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, err)
	}
	return vars, nil
}

// ParseDotenv parses KEY=VALUE lines. Blank lines and lines starting with #
// are skipped, an optional "export " prefix is allowed, values may be wrapped
// in single or double quotes, and an unquoted value ends at " #".
func ParseDotenv(r io.Reader) (map[string]string, error) {
	vars := map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '='", n)
		}
		key = strings.TrimSpace(key)
		if !envKeyRE.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid variable name", n)
		}
		v, err := dotenvValue(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", n, key, err)
		}
		vars[key] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return vars, nil
}

func dotenvValue(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if q := v[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(v[1:], q)
		if end < 0 {
			return "", errors.New("unterminated quote")
		}
		rest := strings.TrimSpace(v[end+2:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("unexpected text after closing quote")
		}
		return v[1 : end+1], nil
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v), nil
}

// Getenv returns a lookup that prefers the process environment (lookup) and
// falls back to the values read from a .env file.
func Getenv(lookup func(string) (string, bool), file map[string]string) func(string) string {
	return func(key string) string {
		if v, ok := lookup(key); ok {
			return v
		}
		return file[key]
	}
}
