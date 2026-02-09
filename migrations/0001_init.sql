CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS keys (
  agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  public_key_multibase TEXT NOT NULL UNIQUE,
  primary_key BOOLEAN NOT NULL DEFAULT FALSE,
  valid_from TIMESTAMPTZ,
  valid_to TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revocation_reason TEXT,
  origin JSONB,
  PRIMARY KEY (agent_id, key_id)
);

CREATE TABLE IF NOT EXISTS attestations (
  attestation_id TEXT PRIMARY KEY,
  subject_agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  issuer_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  type TEXT NOT NULL,
  statement JSONB NOT NULL,
  signature JSONB NOT NULL,
  issued_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS controllers (
  agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  controller_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  role TEXT,
  delegation JSONB,
  PRIMARY KEY (agent_id, controller_agent_id)
);

CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_display_name ON agents USING GIN ((data->>'display_name') gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON agents USING GIN ((data->'endpoints'));
