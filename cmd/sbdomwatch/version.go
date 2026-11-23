package main

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			info := struct {
				Version   string `json:"version"`
				GoVersion string `json:"go_version"`
				Platform  string `json:"platform"`
			}{a.version, runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH}
			if a.output == "json" {
				return json.NewEncoder(a.stdout).Encode(info)
			}
			_, err := fmt.Fprintf(a.stdout, "sbdomwatch %s (%s, %s)\n", info.Version, info.GoVersion, info.Platform)
			return err
		},
	}
}
