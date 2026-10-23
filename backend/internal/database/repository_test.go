package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"n-api-p/internal/audit"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsAuditMetadataDatabaseUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "closed connection", err: sql.ErrConnDone, want: true},
		{name: "bad driver connection", err: driver.ErrBadConn, want: true},
		{name: "closed pgx connection", err: pgconn.ErrConnClosed, want: true},
		{name: "pgx connection attempt", err: &pgconn.ConnectError{}, want: true},
		{name: "connection exception", err: &pgconn.PgError{Code: "08006"}, want: true},
		{name: "insufficient resources", err: &pgconn.PgError{Code: "53300"}, want: true},
		{name: "server shutdown", err: &pgconn.PgError{Code: "57P01"}, want: true},
		{name: "server crash", err: &pgconn.PgError{Code: "57P02"}, want: true},
		{name: "server starting", err: &pgconn.PgError{Code: "57P03"}, want: true},
		{name: "idle connection closed", err: &pgconn.PgError{Code: "57P05"}, want: true},
		{name: "network operation", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("synthetic connection failure")}, want: true},
		{name: "wrapped connection reset", err: fmt.Errorf("query: %w", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), want: true},
		{name: "nil", err: nil, want: false},
		{name: "request deadline", err: context.DeadlineExceeded, want: false},
		{name: "request cancellation", err: context.Canceled, want: false},
		{name: "wrapped request deadline", err: fmt.Errorf("query: %w", context.DeadlineExceeded), want: false},
		{name: "network wrapped deadline", err: &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}, want: false},
		{name: "network wrapped cancellation", err: &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}, want: false},
		{name: "deadline with closed connection", err: errors.Join(context.DeadlineExceeded, pgconn.ErrConnClosed), want: false},
		{name: "cancellation with closed connection", err: errors.Join(context.Canceled, sql.ErrConnDone), want: false},
		{name: "generic timeout", err: os.ErrDeadlineExceeded, want: false},
		{name: "query error", err: &pgconn.PgError{Code: "42601"}, want: false},
		{name: "missing table", err: &pgconn.PgError{Code: "42P01"}, want: false},
		{name: "permission failure", err: &pgconn.PgError{Code: "42501"}, want: false},
		{name: "constraint failure", err: &pgconn.PgError{Code: "23505"}, want: false},
		{name: "statement cancelled", err: &pgconn.PgError{Code: "57014"}, want: false},
		{name: "out of memory", err: &pgconn.PgError{Code: "53200"}, want: false},
		{name: "disk full", err: &pgconn.PgError{Code: "53100"}, want: false},
		{name: "configuration limit", err: &pgconn.PgError{Code: "53400"}, want: false},
		{name: "system error", err: &pgconn.PgError{Code: "58000"}, want: false},
		{name: "missing file", err: &pgconn.PgError{Code: "58P01"}, want: false},
		{name: "duplicate file", err: &pgconn.PgError{Code: "58P02"}, want: false},
		{name: "database removed", err: &pgconn.PgError{Code: "57P04"}, want: false},
		{name: "unexpected repository error", err: errors.New("synthetic mapping failure"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isAuditMetadataDatabaseUnavailable(test.err); got != test.want {
				t.Fatalf("isAuditMetadataDatabaseUnavailable(%T) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestAuditMetadataRepositoryClassifiesQueryAndRowFailures(t *testing.T) {
	failures := []struct {
		name        string
		err         error
		unavailable bool
	}{
		{name: "connection exception", err: &pgconn.PgError{Code: "08006", Message: "synthetic connection failure"}, unavailable: true},
		{name: "closed pgx connection", err: pgconn.ErrConnClosed, unavailable: true},
		{name: "bad driver connection", err: driver.ErrBadConn, unavailable: true},
		{name: "request deadline", err: context.DeadlineExceeded},
		{name: "request cancellation", err: context.Canceled},
		{name: "network wrapped deadline", err: &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}},
		{name: "SQL syntax", err: &pgconn.PgError{Code: "42601", Message: "synthetic query failure"}},
		{name: "SQL resources", err: &pgconn.PgError{Code: "53200", Message: "synthetic resource failure"}},
		{name: "unknown", err: errors.New("synthetic repository failure")},
	}
	for _, failure := range failures {
		for _, stage := range []string{"query", "next", "close"} {
			for _, operation := range []string{"list", "get"} {
				t.Run(failure.name+"/"+stage+"/"+operation, func(t *testing.T) {
					connector := &auditMetadataTestConnector{}
					switch stage {
					case "query":
						connector.queryErr = failure.err
					case "next":
						connector.nextErr = failure.err
					case "close":
						connector.closeErr = failure.err
					}
					repository := newAuditMetadataTestRepository(t, connector)
					var err error
					if operation == "list" {
						_, err = repository.ListAuditMetadata(context.Background(), audit.MetadataFilter{Limit: 25})
					} else {
						_, err = repository.GetAuditMetadata(context.Background(), "84000000-0000-0000-0000-000000000001")
					}
					if !errors.Is(err, failure.err) {
						t.Fatalf("%s() error = %v, want original error", operation, err)
					}
					if errors.Is(err, audit.ErrMetadataUnavailable) != failure.unavailable {
						t.Fatalf("%s() unavailable = %t, want %t", operation, errors.Is(err, audit.ErrMetadataUnavailable), failure.unavailable)
					}
					if connector.queries == 0 {
						t.Fatal("metadata query did not reach the synthetic driver")
					}
				})
			}
		}
	}
}

func TestAuditMetadataRepositoryPreservesScanAndValidationErrors(t *testing.T) {
	for _, operation := range []string{"list", "get"} {
		t.Run("scan/"+operation, func(t *testing.T) {
			repository := newAuditMetadataTestRepository(t, &auditMetadataTestConnector{scanFailure: true})
			var err error
			if operation == "list" {
				_, err = repository.ListAuditMetadata(context.Background(), audit.MetadataFilter{Limit: 25})
			} else {
				_, err = repository.GetAuditMetadata(context.Background(), "84000000-0000-0000-0000-000000000001")
			}
			if err == nil || errors.Is(err, audit.ErrMetadataUnavailable) || errors.Is(err, audit.ErrMetadataNotFound) {
				t.Fatalf("%s() error = %v, want unclassified scan failure", operation, err)
			}
		})
	}
	connector := &auditMetadataTestConnector{}
	repository := newAuditMetadataTestRepository(t, connector)
	for _, filter := range []audit.MetadataFilter{{Limit: 0}, {Limit: audit.MaxMetadataPageSize + 1}, {Limit: 25, Cursor: "invalid cursor"}} {
		if _, err := repository.ListAuditMetadata(context.Background(), filter); !errors.Is(err, audit.ErrInvalidMetadataRequest) {
			t.Fatalf("ListAuditMetadata() error = %v, want invalid request", err)
		}
	}
	if connector.queries != 0 {
		t.Fatal("invalid metadata request reached the driver")
	}
	if page, err := repository.ListAuditMetadata(context.Background(), audit.MetadataFilter{Limit: 25}); err != nil || len(page.Records) != 0 || page.NextCursor != "" {
		t.Fatalf("ListAuditMetadata() = (%+v, %v), want empty page", page, err)
	}
	if _, err := repository.GetAuditMetadata(context.Background(), "84000000-0000-0000-0000-000000000001"); !errors.Is(err, audit.ErrMetadataNotFound) {
		t.Fatalf("GetAuditMetadata() error = %v, want not found", err)
	}
}

func newAuditMetadataTestRepository(t *testing.T, connector *auditMetadataTestConnector) *Repository {
	t.Helper()
	database := sql.OpenDB(connector)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close synthetic database: %v", err)
		}
	})
	return NewRepository(database)
}

type auditMetadataTestConnector struct {
	queryErr    error
	nextErr     error
	closeErr    error
	scanFailure bool
	queries     int
}

func (connector *auditMetadataTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &auditMetadataTestConnection{connector: connector}, nil
}

func (connector *auditMetadataTestConnector) Driver() driver.Driver { return connector }
func (*auditMetadataTestConnector) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected synthetic driver open")
}

type auditMetadataTestConnection struct{ connector *auditMetadataTestConnector }

func (*auditMetadataTestConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected synthetic prepare")
}
func (*auditMetadataTestConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected synthetic transaction")
}
func (*auditMetadataTestConnection) Close() error { return nil }
func (connection *auditMetadataTestConnection) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	connection.connector.queries++
	if connection.connector.queryErr != nil {
		return nil, connection.connector.queryErr
	}
	return &auditMetadataTestRows{connector: connection.connector}, nil
}

type auditMetadataTestRows struct{ connector *auditMetadataTestConnector }

func (*auditMetadataTestRows) Columns() []string { return []string{"synthetic_column"} }
func (rows *auditMetadataTestRows) Close() error { return rows.connector.closeErr }
func (rows *auditMetadataTestRows) Next([]driver.Value) error {
	if rows.connector.nextErr != nil {
		return rows.connector.nextErr
	}
	if rows.connector.scanFailure {
		return nil
	}
	return io.EOF
}
