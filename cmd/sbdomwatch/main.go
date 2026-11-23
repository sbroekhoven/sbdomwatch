// Command sbdomwatch is the domain and DNS watcher: `sbdomwatch serve` runs
// the service, the other subcommands are the CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Stable exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	// exitNotFound (3) arrives with the watch commands.
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
	var ce *codeError
	if errors.As(err, &ce) {
		if ce.code == exitUsage {
			fmt.Fprintf(stderr, "Run '%s --help' for usage.\n", root.CommandPath())
		}
		return ce.code
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
