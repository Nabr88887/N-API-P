package httpapi

import (
	"errors"
	"net/http"

	"n-api-p/internal/observability"
)

var ErrInvalidOperatorMetricsDependencies = errors.New("invalid operator metrics dependencies")

type OperatorMetricsDependencies struct {
	Authorize func(*http.Request) bool
	Metrics   *observability.Metrics
}

func NewOperatorMetricsRouter(dependencies OperatorMetricsDependencies) (http.Handler, error) {
	if dependencies.Authorize == nil || dependencies.Metrics == nil {
		return nil, ErrInvalidOperatorMetricsDependencies
	}
	route := routeByNameValue(RouteName("operations.metrics"))
	if route.Pattern != "/metrics" || route.Method != MethodGet || route.Surface != SurfaceOperations || route.Auth != AuthOperatorBoundary {
		return nil, ErrInvalidOperatorMetricsDependencies
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", operatorMetricsHandler(dependencies.Authorize, dependencies.Metrics))
	return observability.NewRequestIDMiddlewareWithMetrics(mux, observability.DefaultLogger(), dependencies.Metrics), nil
}

func operatorMetricsHandler(authorize func(*http.Request) bool, metrics *observability.Metrics) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !authorize(request) {
			writeErrorResponse(writer, CodeForbidden)
			return
		}
		metrics.Handler().ServeHTTP(writer, request)
	})
}
