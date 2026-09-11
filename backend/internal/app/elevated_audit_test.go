package app

import (
	"database/sql"
	"testing"
)

func TestElevatedAuditRepositoryHasIndependentEightConnectionBudget(t *testing.T) {
	pool := &sql.DB{}
	newElevatedAuditRepository(pool)
	if pool.Stats().MaxOpenConnections != 8 {
		t.Fatalf("bulk connection limit=%d, want 8", pool.Stats().MaxOpenConnections)
	}
}
