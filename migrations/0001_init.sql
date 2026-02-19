CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS bots (
  bot_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS keys (
  bot_id TEXT NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  public_key_multibase TEXT NOT NULL UNIQUE,
  primary_key BOOLEAN NOT NULL DEFAULT FALSE,
  valid_from TIMESTAMPTZ,
  valid_to TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revocation_reason TEXT,
  origin JSONB,
  PRIMARY KEY (bot_id, key_id)
);

CREATE TABLE IF NOT EXISTS attestations (
  attestation_id TEXT PRIMARY KEY,
  subject_bot_id TEXT NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
  issuer_bot_id TEXT NOT NULL REFERENCES bots(bot_id),
  type TEXT NOT NULL,
  statement JSONB NOT NULL,
  signature JSONB NOT NULL,
  issued_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS controllers (
  bot_id TEXT NOT NULL REFERENCES bots(bot_id) ON DELETE CASCADE,
  controller_bot_id TEXT NOT NULL REFERENCES bots(bot_id),
  role TEXT,
  delegation JSONB,
  PRIMARY KEY (bot_id, controller_bot_id)
);

CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_bots_status ON bots(status);
CREATE INDEX IF NOT EXISTS idx_bots_display_name ON bots USING GIN ((data->>'display_name') gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON bots USING GIN ((data->'endpoints'));
