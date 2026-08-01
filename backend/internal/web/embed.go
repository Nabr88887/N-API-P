package web

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var staticFiles embed.FS

func Assets() (fs.FS, error) {
	return fs.Sub(staticFiles, "static/build")
}
