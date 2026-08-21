package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"n-api-p/internal/app"
	"n-api-p/internal/config"
	"n-api-p/internal/observability"
)

func main() {
	logger := observability.NewStdoutLogger()
	cfg, secrets, err := config.LoadStartupFromEnvironment()
	if err != nil {
		if logErr := logger.Emit(observability.LogEvent{
			Level:     observability.LevelError,
			Event:     "startup_configuration_rejected",
			ErrorCode: "startup_configuration_rejected",
		}); logErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}

	application, err := app.New(cfg, secrets)
	if err != nil {
		_ = logger.Emit(observability.LogEvent{Level: observability.LevelError, Event: "startup_composition_rejected", ErrorCode: "startup_composition_rejected"})
		os.Exit(1)
	}
	defer application.Close()
	if err := logger.Emit(observability.LogEvent{Level: observability.LevelInfo, Event: "startup_composition_accepted"}); err != nil {
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := application.Start(ctx); err != nil {
		_ = logger.Emit(observability.LogEvent{Level: observability.LevelError, Event: "startup_recovery_rejected", ErrorCode: "startup_recovery_rejected"})
		os.Exit(1)
	}
	go func() {
		if serveErr := application.Server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Print("http server stopped")
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	_ = application.Server.Close()
}
