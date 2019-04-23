CREATE TABLE unique_email_addresses (
  id INTEGER NOT NULL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users (id),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  email_as_entered TEXT NOT NULL,
  email_without_labels TEXT NOT NULL)
