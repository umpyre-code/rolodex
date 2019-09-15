ALTER TABLE clients DROP CONSTRAINT clients_phone_number_key;

CREATE TABLE phone_numbers (
  id BIGSERIAL PRIMARY KEY,
  client_id BIGINT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  number TEXT NOT NULL UNIQUE,
  country_code TEXT NOT NULL)
