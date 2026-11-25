// Package web holds the single-page dashboard asset embedded into every binary.
package web

import "embed"

// FS contains the self-contained HTML/CSS/JS dashboard. The asset lives in this
// directory because //go:embed cannot reference a parent directory.
//
//go:embed index.html
var FS embed.FS
