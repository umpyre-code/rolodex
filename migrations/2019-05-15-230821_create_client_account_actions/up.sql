CREATE TABLE client_account_actions (
  id BIGSERIAL PRIMARY KEY,
  client_id BIGINT NOT NULL REFERENCES clients (id),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  action ACCOUNT_ACTION,
  ip_address TEXT,
  region TEXT,
  region_subdivision TEXT,
  city TEXT)
