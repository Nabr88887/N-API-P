package database

import "n-api-p/internal/audit"

var _ audit.PendingAuditRepository = (*Repository)(nil)
var _ audit.FinalAuditRepository = (*Repository)(nil)
var _ audit.DegradedRepository = (*Repository)(nil)
