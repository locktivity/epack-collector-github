// Package schema embeds the collector's JSON Schemas and its trace map, so
// the collector can check its own output against them when it emits.
package schema

import _ "embed"

// Detailed is the JSON Schema of the detailed artifact, artifacts/github.json.
//
//go:embed v1.0.0.json
var Detailed []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte
