// Package webui bettet die gebaute Svelte-Oberfläche ein (npm run build → dist/).
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

func FS() fs.FS {
	f, _ := fs.Sub(dist, "dist")
	return f
}
