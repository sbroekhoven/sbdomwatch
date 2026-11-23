package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/api"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

func (a *app) importCmd() *cobra.Command {
	var f addFlags
	cmd := &cobra.Command{
		Use:   "import <file|->",
		Short: "Add every domain in a file (one per line, # starts a comment)",
		Long: "Add every domain in a file with the same template, reason and tags.\n" +
			"All lines are validated first; if any line is invalid nothing is sent.\n" +
			"Domains are sent in batches of up to 1000; each batch is all or nothing.",
		Example: `  sbdomwatch import owned.txt --template owned --reason "company domain"
  sbdomwatch import - --template candidate --reason "sbsquat run 42" < candidates.txt`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := f.request("example.com"); err != nil {
				return err // flag problems first
			}
			var in io.Reader = cmd.InOrStdin()
			if args[0] != "-" {
				file, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("open %s: %w", args[0], err)
				}
				defer file.Close()
				in = file
			}
			reqs, err := readImport(in, &f)
			if err != nil {
				return err
			}
			if len(reqs) == 0 {
				return usageError(errors.New("no domains in input"))
			}
			c, err := a.newClient()
			if err != nil {
				return err
			}
			var total api.BulkResponse
			for start := 0; start < len(reqs); start += api.MaxBulkItems {
				end := min(start+api.MaxBulkItems, len(reqs))
				res, err := c.BulkAdd(cmd.Context(), reqs[start:end])
				if err != nil {
					if start > 0 {
						return fmt.Errorf("batch starting at domain %d failed (earlier batches were stored): %w", start+1, err)
					}
					return err
				}
				total.Created += res.Created
				total.Merged += res.Merged
				total.Unchanged += res.Unchanged
				total.Results = append(total.Results, res.Results...)
			}
			if a.output == "json" {
				return writeJSON(a.stdout, total)
			}
			_, err = fmt.Fprintf(a.stdout, "imported %d domain(s): %d added, %d merged, %d unchanged\n",
				len(reqs), total.Created, total.Merged, total.Unchanged)
			return err
		},
	}
	f.register(cmd)
	return cmd
}

// readImport parses and validates every line. It reports all invalid lines
// at once as a usage error. Duplicates after normalization are dropped.
func readImport(r io.Reader, f *addFlags) ([]watch.AddRequest, error) {
	var (
		reqs []watch.AddRequest
		errs []string
		seen = map[string]bool{}
	)
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		req, err := f.request(line)
		if err != nil {
			errs = append(errs, fmt.Sprintf("line %d: %v", n, err))
			continue
		}
		if seen[req.Domain] {
			continue
		}
		seen[req.Domain] = true
		reqs = append(reqs, req)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(errs) > 0 {
		return nil, usageError(fmt.Errorf("%d invalid line(s), nothing imported:\n  %s", len(errs), strings.Join(errs, "\n  ")))
	}
	return reqs, nil
}
