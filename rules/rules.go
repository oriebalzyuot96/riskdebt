// Package rules embeds the shared rule data used by every riskdebt implementation.
package rules

import _ "embed"

//go:embed meta.json
var Meta []byte

//go:embed secrets.json
var Secrets []byte

//go:embed eol.json
var EOL []byte

//go:embed compromised.json
var Compromised []byte

//go:embed patterns.json
var Patterns []byte
