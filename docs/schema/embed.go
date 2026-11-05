// Package schema embeds the collector's JSON Schemas and its trace map, so
// the collector can check its own output against them when it emits.
package schema

import (
	_ "embed"
	"encoding/json"
)

// Detailed is the JSON Schema of the detailed artifact,
// artifacts/github.details.json.
//
//go:embed v1.0.0.json
var Detailed []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// methods is methods.json. It holds one plain sentence on how the collector
// measures each value of the access-posture and vuln-scanning artifacts that
// is not a copy of a detailed value, keyed by schema ID and then by field.
//
//go:embed methods.json
var methods []byte

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods. Each one becomes the x-epack-method of
// its field in the SDK's schema for the artifact's type.
func Methods() map[string]map[string]string {
	var bySchema map[string]map[string]string
	if err := json.Unmarshal(methods, &bySchema); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return bySchema
}
