package main

import (
	"os"
	"time"

	"n-api-p/internal/healthcheck"
)

func main() {
	if healthcheck.CheckFromEnvironment(2*time.Second) != nil {
		os.Exit(1)
	}
}
