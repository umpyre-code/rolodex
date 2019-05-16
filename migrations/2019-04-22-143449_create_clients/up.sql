CREATE TABLE clients (
  id BIGSERIAL PRIMARY KEY,
  uuid UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4 (),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  full_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  phone_number TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL)
