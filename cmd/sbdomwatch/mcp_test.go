package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPOverStdio builds the real binary, runs `sbdomwatch mcp` as a
// subprocess against a test API server and speaks MCP to it over stdio:
// initialize, tools/list, tools/call.
func TestMCPOverStdio(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	e := newCLIEnv(t)
	bin := filepath.Join(t.TempDir(), "sbdomwatch")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	connect := func(args ...string) *mcp.ClientSession {
		t.Helper()
		cmd := exec.Command(bin, append([]string{"--env-file", filepath.Join(t.TempDir(), "none"), "mcp"}, args...)...)
		cmd.Env = append(os.Environ(),
			"SBDOMWATCH_URL="+e.env["SBDOMWATCH_URL"],
			"SBDOMWATCH_TOKEN="+e.env["SBDOMWATCH_TOKEN"],
		)
		cmd.Stderr = os.Stderr
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "stdio-test"}, nil).Connect(t.Context(), &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cs.Close() })
		return cs
	}

	cs := connect("--allow-writes", "--actor", "claude")
	if info := cs.InitializeResult(); info.ServerInfo.Name != "sbdomwatch" || !strings.Contains(info.Instructions, "untrusted-data") {
		t.Errorf("initialize result = %+v", info)
	}
	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	if !slices.Contains(names, "add_watch") || len(names) != 7 {
		t.Errorf("tools = %v", names)
	}
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "add_watch", Arguments: map[string]any{
		"domain": "example.com", "template": "owned", "reason": "added over stdio",
	}})
	if err != nil || res.IsError {
		t.Fatalf("add_watch: %v %+v", err, res)
	}
	res, err = cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_watches"})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "example.com") {
		t.Fatalf("list_watches: %v %+v", err, res)
	}
	w, err := e.st.GetWatch(t.Context(), "example.com")
	if err != nil || w.Origins[0].AddedBy != "claude" {
		t.Errorf("stored origin = %+v, %v (want added_by claude)", w.Origins, err)
	}

	// Without --allow-writes only the read tools exist.
	tools, err = connect().ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 4 {
		t.Errorf("read-only server lists %d tools, %v", len(tools.Tools), err)
	}
}
