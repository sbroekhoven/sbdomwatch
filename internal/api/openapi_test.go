package api

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/sbroekhoven/sbdomwatch/internal/diff"
	"github.com/sbroekhoven/sbdomwatch/internal/events"
	"github.com/sbroekhoven/sbdomwatch/internal/store"
	"github.com/sbroekhoven/sbdomwatch/internal/watch"
)

type openAPIDoc struct {
	OpenAPI    string                    `yaml:"openapi"`
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]any `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) openAPIDoc {
	t.Helper()
	var doc openAPIDoc
	if err := yaml.Unmarshal(OpenAPI, &doc); err != nil {
		t.Fatalf("openapi.yaml: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi version %q", doc.OpenAPI)
	}
	return doc
}

// TestOpenAPIMatchesRoutes: every route is documented and every documented
// operation exists.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	doc := loadSpec(t)
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		for method := range ops {
			if method == "parameters" {
				continue
			}
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}
	served := map[string]bool{"GET /healthz": true, "GET /openapi.yaml": true}
	s := New(":0", Deps{Log: discard()})
	for _, r := range s.routeTable() {
		if r.pattern == "/v1/watches/{target}" {
			for _, v := range actionVerbs {
				served[r.method+" /v1/watches/{domain}:"+v] = true
			}
			continue
		}
		served[r.method+" "+r.pattern] = true
	}
	for op := range served {
		if !documented[op] {
			t.Errorf("served but not in openapi.yaml: %s", op)
		}
	}
	for op := range documented {
		if !served[op] {
			t.Errorf("in openapi.yaml but not served: %s", op)
		}
	}
}

// TestOpenAPIMatchesTypes: the documented schemas list exactly the JSON
// fields of the Go types.
func TestOpenAPIMatchesTypes(t *testing.T) {
	doc := loadSpec(t)
	types := map[string]any{
		"Watch":         watch.Watch{},
		"Origin":        watch.Origin{},
		"AddRequest":    watch.AddRequest{},
		"AddResult":     store.AddResult{},
		"TimelineEntry": store.TimelineEntry{},
		"Change":        diff.Change{},
		"Payload":       events.Payload{},
		"Event":         events.Event{},
	}
	for name, v := range types {
		schema, ok := doc.Components.Schemas[name]
		if !ok {
			t.Errorf("schema %s missing", name)
			continue
		}
		var fields []string
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
			if tag != "" && tag != "-" {
				fields = append(fields, tag)
			}
		}
		slices.Sort(fields)
		documented := slices.Sorted(maps.Keys(schema.Properties))
		if !slices.Equal(fields, documented) {
			t.Errorf("schema %s: Go fields %v, documented %v", name, fields, documented)
		}
	}
}

func TestOpenAPIServed(t *testing.T) {
	h := New(":0", Deps{Log: discard()}).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/yaml" || !strings.HasPrefix(rec.Body.String(), "openapi: 3.1.0") {
		t.Errorf("GET /openapi.yaml: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}
