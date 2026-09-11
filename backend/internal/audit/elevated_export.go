package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"n-api-p/internal/access"
)

const elevatedAuditExportSlots = 2

var (
	ErrInvalidElevatedAuditExport    = errors.New("invalid elevated audit export")
	ErrElevatedAuditExportIncomplete = errors.New("elevated audit export incomplete")
)

type ElevatedAuditExportInput struct {
	Session   access.ActivePortalSession
	RequestID string
	Query     ElevatedAuditQuery
}

type ElevatedAuditExportService struct {
	query        *ElevatedAuditQueryService
	now          func() time.Time
	newID        func() (string, error)
	queryTimeout time.Duration
	slots        chan struct{}
	failureGate  FailureGate
}

func (service *ElevatedAuditExportService) SetFailureGate(gate FailureGate) {
	service.failureGate = gate
}

func NewElevatedAuditExportService(query *ElevatedAuditQueryService) (*ElevatedAuditExportService, error) {
	if query == nil {
		return nil, ErrInvalidElevatedAuditExport
	}
	return &ElevatedAuditExportService{query: query, now: time.Now, newID: newRawViewRequestID, queryTimeout: elevatedAuditQueryTimeout, slots: make(chan struct{}, elevatedAuditExportSlots)}, nil
}

func (service *ElevatedAuditExportService) Export(ctx context.Context, input ElevatedAuditExportInput, writer io.Writer) error {
	if service == nil || service.query == nil || service.now == nil || service.newID == nil || service.queryTimeout <= 0 || service.slots == nil || writer == nil {
		return ErrInvalidElevatedAuditExport
	}
	now := service.now().UTC()
	if !validElevatedAuditSession(input.Session, now) {
		return access.ErrForbidden
	}
	if !validMetadataID(strings.TrimSpace(input.RequestID)) {
		return ErrInvalidElevatedAuditExport
	}
	normalized, selection, err := normalizeElevatedAuditQuery(input.Query, now)
	if err != nil {
		return err
	}
	startCtx, cancelStart := context.WithTimeout(ctx, service.queryTimeout)
	defer cancelStart()
	select {
	case service.slots <- struct{}{}:
		defer func() { <-service.slots }()
	case <-startCtx.Done():
		return errors.Join(ErrElevatedAuditExportIncomplete, startCtx.Err())
	}
	grant, err := service.query.repository.FindElevatedAuditGrant(startCtx, ElevatedAuditGrantLookup{ActorIdentityID: input.Session.IdentityID, SessionID: input.Session.SessionID, At: service.now().UTC()})
	if err != nil {
		return err
	}
	if err := service.query.checkGrant(startCtx, input.Session, grant.ID); err != nil {
		return err
	}
	if input.Query.Cursor != "" {
		cursor, err := service.query.decodeCursor(input.Query.Cursor, grant.ID, hashElevatedAuditQuery(normalized), now)
		if err != nil {
			return err
		}
		if cursor.VisibleAt.Before(grant.IssuedAt) {
			return ErrInvalidElevatedAuditCursor
		}
		selection.Cursor = &cursor.Position
		selection.SnapshotAt = cursor.VisibleAt
	}
	if err := service.appendEvent(startCtx, input.Session, grant, input.RequestID, access.SecurityEvent{EventType: "audit_export_start", Outcome: access.SecurityEventSuccess, DetailCode: "export_started", QueryMetadata: normalized.auditMetadata()}); err != nil {
		return err
	}
	cancelStart()

	var count int64
	streamErr := service.stream(ctx, input, grant, normalized, selection, writer, &count)
	terminal := access.SecurityEvent{EventType: "audit_export_terminal", Outcome: access.SecurityEventSuccess, DetailCode: "export_completed", QueryMetadata: normalized.auditMetadata(), ResultCount: &count}
	if streamErr != nil {
		terminal.Outcome = access.SecurityEventFailure
		terminal.DetailCode = "export_incomplete"
	}
	terminalCtx, cancelTerminal := context.WithTimeout(context.WithoutCancel(ctx), service.queryTimeout)
	defer cancelTerminal()
	terminalErr := service.appendEvent(terminalCtx, input.Session, grant, input.RequestID, terminal)
	if streamErr != nil || terminalErr != nil {
		return errors.Join(ErrElevatedAuditExportIncomplete, streamErr, terminalErr)
	}
	return nil
}

func (service *ElevatedAuditExportService) stream(ctx context.Context, input ElevatedAuditExportInput, grant ElevatedAuditGrant, query normalizedElevatedAuditQuery, selection ElevatedAuditSelection, writer io.Writer, count *int64) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		selection.VisibleAt = service.now().UTC()
		queryCtx, cancel := context.WithTimeout(ctx, service.queryTimeout)
		candidates, err := service.query.repository.ListElevatedAuditCandidates(queryCtx, selection)
		cancel()
		if err != nil {
			return fmt.Errorf("select export candidates: %w", err)
		}
		for _, candidate := range candidates {
			if err := service.writeCandidate(ctx, input.Session, grant, query.FullText, candidate, writer, count); err != nil {
				return err
			}
			selection.Cursor = candidatePosition(candidate)
		}
		if len(candidates) < selection.Limit {
			finalCtx, cancelFinal := context.WithTimeout(ctx, service.queryTimeout)
			defer cancelFinal()
			return service.query.checkGrant(finalCtx, input.Session, grant.ID)
		}
	}
}

func (service *ElevatedAuditExportService) writeCandidate(ctx context.Context, session access.ActivePortalSession, grant ElevatedAuditGrant, fullText string, candidate ElevatedAuditCandidate, writer io.Writer, written *int64) error {
	recordCtx, cancel := context.WithTimeout(ctx, service.queryTimeout)
	defer cancel()
	if err := service.query.checkGrant(recordCtx, session, grant.ID); err != nil {
		return err
	}
	record, matched, err := service.query.readCandidate(recordCtx, candidate, fullText, service.now().UTC(), false)
	if err != nil {
		return err
	}
	defer clear(record.RequestJSON)
	defer clear(record.ResponseJSON)
	if !matched {
		return nil
	}
	if err := service.query.checkGrant(recordCtx, session, grant.ID); err != nil {
		return err
	}
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode export record: %w", err)
	}
	line = append(line, '\n')
	defer clear(line)
	count, err := writer.Write(line)
	if err != nil {
		return fmt.Errorf("write export record: %w", err)
	}
	if count != len(line) {
		return io.ErrShortWrite
	}
	*written++
	return nil
}

func (service *ElevatedAuditExportService) appendEvent(ctx context.Context, session access.ActivePortalSession, grant ElevatedAuditGrant, requestID string, event access.SecurityEvent) error {
	eventID, err := service.newID()
	if err != nil {
		return access.ErrSecurityAuditUnavailable
	}
	event.ID = eventID
	event.ActorIdentityID = session.IdentityID
	event.SessionID = session.SessionID
	event.GrantID = grant.ID
	event.RequestID = requestID
	event.Reason = grant.Purpose
	event.OccurredAt = service.now().UTC()
	if err := service.query.repository.AppendSecurityEvent(ctx, event); err != nil {
		if service.failureGate != nil {
			return errors.Join(access.ErrSecurityAuditUnavailable, service.failureGate.Block(ctx, GateReasonFinalizationPersistence))
		}
		return access.ErrSecurityAuditUnavailable
	}
	return nil
}
