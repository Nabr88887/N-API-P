package main

import (
	"os"

	"n-api-p/internal/config"
	"n-api-p/internal/observability"
)

func main() {
	logger := observability.NewStdoutLogger()
	if _, _, err := config.LoadStartupFromEnvironment(); err != nil {
		if logErr := logger.Emit(observability.LogEvent{
			Level:     observability.LevelError,
			Event:     "startup_configuration_rejected",
			ErrorCode: "startup_configuration_rejected",
		}); logErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}

	if err := logger.Emit(observability.LogEvent{Level: observability.LevelInfo, Event: "startup_configuration_accepted"}); err != nil {
		os.Exit(1)
	}
}
