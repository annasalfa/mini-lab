CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE IF NOT EXISTS secrets (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL,
  owner_id UUID NOT NULL,
  key_id TEXT NOT NULL,
  key_version INT NOT NULL,
  wrapped_dek TEXT NOT NULL,
  iv BYTEA NOT NULL,
  tag BYTEA NOT NULL,
  ciphertext BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
