ALTER TABLE api_keys
    ALTER COLUMN verification_hash DROP NOT NULL;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_hash_valid;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_hash_valid CHECK (
        (status = 'active' AND verification_hash IS NOT NULL AND octet_length(verification_hash) > 0)
        OR (status = 'revoked' AND (verification_hash IS NULL OR octet_length(verification_hash) > 0))
    );
