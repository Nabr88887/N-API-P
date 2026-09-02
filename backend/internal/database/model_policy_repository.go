package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"n-api-p/internal/access"
	"n-api-p/internal/usage"
)

const listAllowedModelIDsSQL = `
SELECT model_id
FROM model_allowlist
WHERE status = 'allowed'
ORDER BY model_id`

const readModelAllowlistSQL = `
SELECT model_id, status, input_unit_price, output_unit_price, price_version, updated_at, updated_by_identity_id::text
FROM model_allowlist
ORDER BY model_id`

const lockModelAllowlistPolicySQL = `
SELECT id
FROM operational_state
WHERE id = 1
FOR UPDATE`

const upsertModelAllowlistEntrySQL = `
INSERT INTO model_allowlist (model_id, status, input_unit_price, output_unit_price, price_version, updated_at, updated_by_identity_id)
VALUES ($1, $2, NULLIF($3, '')::numeric, NULLIF($4, '')::numeric, NULLIF($5, ''), $6, $7)
ON CONFLICT (model_id) DO UPDATE
SET status = EXCLUDED.status,
    input_unit_price = COALESCE(EXCLUDED.input_unit_price, model_allowlist.input_unit_price),
    output_unit_price = COALESCE(EXCLUDED.output_unit_price, model_allowlist.output_unit_price),
    price_version = COALESCE(EXCLUDED.price_version, model_allowlist.price_version),
    updated_at = EXCLUDED.updated_at,
    updated_by_identity_id = EXCLUDED.updated_by_identity_id`

const deleteOmittedModelAllowlistEntriesSQL = `
DELETE FROM model_allowlist
WHERE NOT (model_id = ANY($1::text[]))`

func (r *Repository) ListAllowedModelIDs(ctx context.Context) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, listAllowedModelIDsSQL)
	if err != nil {
		return nil, fmt.Errorf("list allowed model IDs: %w", err)
	}
	defer rows.Close()
	var modelIDs []string
	for rows.Next() {
		var modelID string
		if err := rows.Scan(&modelID); err != nil {
			return nil, fmt.Errorf("scan allowed model ID: %w", err)
		}
		modelIDs = append(modelIDs, modelID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate allowed model IDs: %w", err)
	}
	return modelIDs, nil
}

// ReadModelPrice returns the immutable price facts currently configured for an
// allowed model. A nil snapshot means the model is allowed but unpriced.
func (r *Repository) ReadModelPrice(ctx context.Context, modelID string) (*usage.PriceSnapshot, error) {
	if r == nil || r.db == nil || modelID == "" {
		return nil, errors.New("invalid model price request")
	}
	var inputPrice, outputPrice, version sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT input_unit_price::text, output_unit_price::text, price_version FROM model_allowlist WHERE model_id = $1 AND status = 'allowed'`, modelID).Scan(&inputPrice, &outputPrice, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read model price: %w", err)
	}
	if !inputPrice.Valid || !outputPrice.Valid || !version.Valid {
		return nil, nil
	}
	return &usage.PriceSnapshot{Version: version.String, InputUnitPrice: inputPrice.String, OutputUnitPrice: outputPrice.String}, nil
}

func (r *Repository) ReadModelAllowlist(ctx context.Context) ([]access.ModelAllowlistEntry, error) {
	rows, err := r.db.QueryContext(ctx, readModelAllowlistSQL)
	if err != nil {
		return nil, fmt.Errorf("read model allowlist: %w", err)
	}
	defer rows.Close()
	var entries []access.ModelAllowlistEntry
	for rows.Next() {
		var entry access.ModelAllowlistEntry
		var inputPrice, outputPrice, priceVersion, updatedBy sql.NullString
		if err := rows.Scan(&entry.ModelID, &entry.Status, &inputPrice, &outputPrice, &priceVersion, &entry.UpdatedAt, &updatedBy); err != nil {
			return nil, fmt.Errorf("scan model allowlist entry: %w", err)
		}
		if inputPrice.Valid {
			entry.InputUnitPrice = inputPrice.String
		}
		if outputPrice.Valid {
			entry.OutputUnitPrice = outputPrice.String
		}
		if priceVersion.Valid {
			entry.PriceVersion = priceVersion.String
		}
		if updatedBy.Valid {
			entry.UpdatedByIdentityID = updatedBy.String
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate model allowlist: %w", err)
	}
	return entries, nil
}

func (r *Repository) ReplaceModelAllowlist(ctx context.Context, change access.ModelAllowlistChange) (entries []access.ModelAllowlistEntry, err error) {
	if err := change.Validate(); err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin model allowlist transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back model allowlist transaction: %w", rollbackErr))
		}
	}()

	if err := requireActiveSystemAdministrator(ctx, tx, change.Event.ActorIdentityID); err != nil {
		return nil, err
	}
	var policyID int
	if err := tx.QueryRowContext(ctx, lockModelAllowlistPolicySQL).Scan(&policyID); err != nil {
		return nil, fmt.Errorf("lock model allowlist policy: %w", err)
	}
	modelIDs := make([]string, 0, len(change.Entries))
	for _, entry := range change.Entries {
		if _, err := tx.ExecContext(ctx, upsertModelAllowlistEntrySQL, entry.ModelID, entry.Status, entry.InputUnitPrice, entry.OutputUnitPrice, entry.PriceVersion, change.ChangedAt.UTC(), change.Event.ActorIdentityID); err != nil {
			return nil, fmt.Errorf("upsert model allowlist entry: %w", err)
		}
		modelIDs = append(modelIDs, entry.ModelID)
	}
	if _, err := tx.ExecContext(ctx, deleteOmittedModelAllowlistEntriesSQL, modelIDs); err != nil {
		return nil, fmt.Errorf("delete omitted model allowlist entries: %w", err)
	}
	event := change.Event
	event.DetailCode = fmt.Sprintf("replaced_%d_models", len(change.Entries))
	if err := appendSecurityEventTx(ctx, tx, event); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, readModelAllowlistSQL)
	if err != nil {
		return nil, fmt.Errorf("read replaced model allowlist: %w", err)
	}
	for rows.Next() {
		var entry access.ModelAllowlistEntry
		var inputPrice, outputPrice, priceVersion, updatedBy sql.NullString
		if err := rows.Scan(&entry.ModelID, &entry.Status, &inputPrice, &outputPrice, &priceVersion, &entry.UpdatedAt, &updatedBy); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan replaced model allowlist entry: %w", err)
		}
		if inputPrice.Valid {
			entry.InputUnitPrice = inputPrice.String
		}
		if outputPrice.Valid {
			entry.OutputUnitPrice = outputPrice.String
		}
		if priceVersion.Valid {
			entry.PriceVersion = priceVersion.String
		}
		if updatedBy.Valid {
			entry.UpdatedByIdentityID = updatedBy.String
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate replaced model allowlist: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close replaced model allowlist: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit model allowlist transaction: %w", err)
	}
	committed = true
	return entries, nil
}

var _ access.ModelAllowlistRepository = (*Repository)(nil)
