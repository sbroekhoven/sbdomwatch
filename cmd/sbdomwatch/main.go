// Command sbdomwatch is the domain and DNS watcher: `sbdomwatch serve` runs
// the service, the other subcommands are the CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sbroekhoven/sbdomwatch/internal/client"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Stable exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitNotFound = 3
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	a := &app{version: version, stdout: stdout, stderr: stderr, lookupEnv: lookupEnv}
	root := a.rootCmd()
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	fmt.Fprintln(stderr, "error:", err)
	code := exitCode(err)
	if code == exitUsage {
		fmt.Fprintf(stderr, "Run '%s --help' for usage.\n", root.CommandPath())
	}
	return code
}

// exitCode maps an error to a stable exit code.
func exitCode(err error) int {
	var ce *codeError
	var ae *client.APIError
	switch {
	case errors.As(err, &ce):
		return ce.code
	case errors.Is(err, client.ErrNotFound):
		return exitNotFound
	case errors.As(err, &ae) && ae.Status == http.StatusBadRequest:
		return exitUsage
	}
	return exitError
}

// codeError carries a specific exit code.
type codeError struct {
	code int
	err  error
}

func (e *codeError) Error() string { return e.err.Error() }
func (e *codeError) Unwrap() error { return e.err }

func usageError(err error) error { return &codeError{code: exitUsage, err: err} }
