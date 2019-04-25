CREATE TABLE unique_email_addresses (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users (id),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  email_as_entered TEXT NOT NULL UNIQUE,
  email_without_labels TEXT NOT NULL)
