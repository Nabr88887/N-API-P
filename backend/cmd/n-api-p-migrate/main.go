package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"n-api-p/internal/database"
	"n-api-p/internal/observability"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(runContext(ctx, os.LookupEnv, time.Now, observability.NewStdoutLogger()))
}

func run(lookup func(string) (string, bool), now func() time.Time, logger *observability.Logger) int {
	return runContext(context.Background(), lookup, now, logger)
}

func runContext(ctx context.Context, lookup func(string) (string, bool), now func() time.Time, logger *observability.Logger) int {
	if ctx == nil || now == nil || logger == nil {
		return 1
	}
	requestID, err := observability.NewRequestID()
	if err != nil {
		return 1
	}
	request, err := database.LoadProductionMigrationRequest(lookup, now())
	if err != nil {
		_ = logger.Emit(observability.LogEvent{
			Level: observability.LevelError, Event: "migration_preflight_rejected",
			RequestID: requestID, ErrorCode: database.MigrationFailureCode(err),
		})
		return 1
	}
	if err := logger.Emit(observability.LogEvent{
		Level: observability.LevelInfo, Event: "migration_preflight_accepted", RequestID: requestID,
	}); err != nil {
		return 1
	}
	if err := database.ApplyProductionMigrations(ctx, request); err != nil {
		_ = logger.Emit(observability.LogEvent{
			Level: observability.LevelError, Event: "migration_execution_rejected",
			RequestID: requestID, ErrorCode: database.MigrationFailureCode(err),
		})
		return 1
	}
	if err := logger.Emit(observability.LogEvent{
		Level: observability.LevelInfo, Event: "migration_execution_completed", RequestID: requestID,
	}); err != nil {
		return 1
	}
	return 0
}
