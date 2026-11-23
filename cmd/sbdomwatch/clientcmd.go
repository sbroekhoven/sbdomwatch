package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/sbroekhoven/sbdomwatch/internal/client"
	"github.com/sbroekhoven/sbdomwatch/internal/config"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

// newClient builds an API client from --url, SBDOMWATCH_URL, the client
// config file and SBDOMWATCH_TOKEN.
func (a *app) newClient() (*client.Client, error) {
	cc, err := config.LoadClient(config.ClientConfigPath(a.getenv))
	if err != nil {
		return nil, err
	}
	base := config.ResolveURL(a.url, a.getenv, cc)
	token := a.getenv(config.EnvToken)
	if token == "" {
		return nil, errors.New(config.EnvToken + " is not set; put it in the environment or in .env")
	}
	if u, err := url.Parse(base); err == nil && u.Scheme == "http" && !isLoopback(u.Hostname()) {
		fmt.Fprintf(a.stderr, "warning: sending the API token over plain http to %s\n", u.Host)
	}
	actor, err := watch.NormalizeActor(a.getenv("USER"))
	if err != nil {
		actor = "cli"
	}
	return client.New(base, token, actor, nil)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
