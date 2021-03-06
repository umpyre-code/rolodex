CREATE TABLE unique_email_addresses (
  id BIGSERIAL PRIMARY KEY,
  client_id BIGINT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  email_as_entered TEXT NOT NULL UNIQUE,
  email_without_labels TEXT NOT NULL)
