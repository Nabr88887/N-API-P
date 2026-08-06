package database

import "n-api-p/internal/access"

var _ access.ServiceAccountRepository = (*Repository)(nil)
