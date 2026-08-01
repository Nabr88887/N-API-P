package main

import (
	"log/slog"
	"os"

	"n-api-p/internal/config"
)

func main() {
	if _, err := config.LoadFromEnvironment(); err != nil {
		slog.Error("startup configuration rejected", "error", err)
		os.Exit(1)
	}

	slog.Info("startup configuration accepted")
}
