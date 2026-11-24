package main

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/sbroekhoven/sbdomwatch/internal/mcpserver"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

func (a *app) mcpCmd() *cobra.Command {
	var (
		allowWrites bool
		actor       string
	)
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve the sbdomwatch API to AI assistants (MCP over stdio)",
		Long: "Run an MCP server on stdin/stdout for AI assistants such as Claude Code or Claude Desktop.\n" +
			"It talks to the sbdomwatch service like the CLI does (--url, SBDOMWATCH_URL, SBDOMWATCH_TOKEN, .env).\n\n" +
			"Read tools: list_watches, get_watch, get_history, list_events.\n" +
			"With --allow-writes also: add_watch, update_watch, archive_watch.\n" +
			"Never offered: hard delete, confirm, rebaseline.\n\n" +
			"Register it in Claude Code with:\n" +
			"  claude mcp add sbdomwatch -- sbdomwatch mcp --env-file /path/to/sbdomwatch/.env",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			who, err := watch.NormalizeActor(actor)
			if err != nil {
				return usageError(err)
			}
			c, err := a.newClientAs(who)
			if err != nil {
				return err
			}
			s := mcpserver.New(c, mcpserver.Options{Version: a.version, AllowWrites: allowWrites})
			// stdout carries the protocol; nothing else may write to it.
			return s.Run(cmd.Context(), &mcp.StdioTransport{})
		},
	}
	cmd.Flags().BoolVar(&allowWrites, "allow-writes", false, "also offer add_watch, update_watch and archive_watch")
	cmd.Flags().StringVar(&actor, "actor", "mcp", "name in the audit log for changes made through MCP")
	return cmd
}
