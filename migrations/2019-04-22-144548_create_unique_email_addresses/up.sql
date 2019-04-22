CREATE TABLE unique_email_addresses (
  id INTEGER NOT NULL PRIMARY KEY,
  user_id INTEGER REFERENCES users (id),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  email_as_entered VARCHAR(255),
  email_without_labels VARCHAR(255))
