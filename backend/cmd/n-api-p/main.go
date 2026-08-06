package main

import (
	"log/slog"
	"os"

	"n-api-p/internal/config"
)

func main() {
	if _, _, err := config.LoadStartupFromEnvironment(); err != nil {
		slog.Error("startup configuration rejected", "error", err)
		os.Exit(1)
	}

	slog.Info("startup configuration accepted")
}
