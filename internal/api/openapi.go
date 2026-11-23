package api

import (
	_ "embed"
	"net/http"
)

// OpenAPI is the API description, the source of truth for clients.
//
//go:embed openapi.yaml
var OpenAPI []byte

func handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(OpenAPI)
}
