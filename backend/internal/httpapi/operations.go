package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/operations"
)

type AdminOperationsService interface {
	Health(context.Context, operations.HealthInput) (operations.Health, error)
	ListEvents(context.Context, operations.ListEventsInput) (operations.EventPage, error)
}

func NewAdminOperationsHealthHandler(service AdminOperationsService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		if service == nil {
			writeOperationsDatabaseFailure(writer)
			return
		}
		health, err := service.Health(request.Context(), operations.HealthInput{Session: session})
		if err != nil {
			writeOperationsDatabaseFailure(writer)
			return
		}
		writeOperationsHealth(writer, health)
	})
}

func NewAdminOperationalEventsHandler(service AdminOperationsService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		if service == nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		filter, err := operationalEventFilter(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		page, err := service.ListEvents(request.Context(), operations.ListEventsInput{Session: session, Filter: filter})
		if err != nil {
			writeOperationsError(writer, err)
			return
		}
		data := make([]OperationalEvent, 0, len(page.Events))
		for _, event := range page.Events {
			if !operations.ValidFaultCode(event.Fault) {
				continue
			}
			severity, detailCode := "recovery", "recovered"
			if event.Active {
				severity, detailCode = "critical", "active"
			}
			data = append(data, OperationalEvent{
				ID: event.ID, EventType: string(event.Fault), Severity: severity,
				DetailCode: detailCode, OccurredAt: event.OccurredAt,
			})
		}
		writer.Header().Set("Cache-Control", "no-store")
		writePagedJSON(writer, http.StatusOK, PagedResponse[OperationalEvent]{
			Data: data, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""},
		})
	})
}

func operationalEventFilter(request *http.Request) (operations.EventFilter, error) {
	limit, err := parsePageLimit(request)
	if err != nil {
		return operations.EventFilter{}, err
	}
	filter := operations.EventFilter{Limit: limit, Cursor: request.URL.Query().Get("cursor")}
	if severity := strings.TrimSpace(request.URL.Query().Get("severity")); severity != "" {
		active := false
		switch severity {
		case "critical":
			active = true
		case "recovery":
		default:
			return operations.EventFilter{}, operations.ErrInvalidEventFilter
		}
		filter.Active = &active
	}
	if filter.From, err = parseOptionalOperationTime(request.URL.Query().Get("from")); err != nil {
		return operations.EventFilter{}, err
	}
	if filter.To, err = parseOptionalOperationTime(request.URL.Query().Get("to")); err != nil {
		return operations.EventFilter{}, err
	}
	if filter.From != nil && filter.To != nil && filter.From.After(*filter.To) {
		return operations.EventFilter{}, operations.ErrInvalidEventFilter
	}
	return filter, nil
}

func parseOptionalOperationTime(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, operations.ErrInvalidEventFilter
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func writeOperationsHealth(writer http.ResponseWriter, health operations.Health) {
	response := HealthResponse{State: HealthStateHealthy, Components: make([]HealthComponent, 0, len(health.Faults)), CheckedAt: health.CheckedAt}
	for _, fault := range health.Faults {
		if !operations.ValidFaultCode(fault.Code) {
			continue
		}
		component := HealthComponent{Name: string(fault.Code), State: HealthStateHealthy, CheckedAt: health.CheckedAt}
		if fault.Active {
			component.State = HealthStateUnhealthy
			component.DetailCode = string(fault.Code)
			response.State = HealthStateUnhealthy
		}
		response.Components = append(response.Components, component)
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, response)
}

func writeOperationsDatabaseFailure(writer http.ResponseWriter) {
	checkedAt := time.Now().UTC()
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, HealthResponse{
		State: HealthStateUnhealthy,
		Components: []HealthComponent{{
			Name: string(operations.FaultDatabaseUnavailable), State: HealthStateUnhealthy,
			DetailCode: string(operations.FaultDatabaseUnavailable), CheckedAt: checkedAt,
		}},
		CheckedAt: checkedAt,
	})
}

func writeOperationsError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrForbidden):
		writeErrorResponse(writer, CodeForbidden)
	case errors.Is(err, operations.ErrInvalidEventFilter):
		writeErrorResponse(writer, CodeInvalidRequest)
	default:
		writeErrorResponse(writer, CodeInternalError)
	}
}
