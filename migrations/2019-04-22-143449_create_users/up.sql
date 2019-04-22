CREATE TABLE users (
  id INTEGER NOT NULL PRIMARY KEY,
  uuid UUID UNIQUE DEFAULT uuid_generate_v4 (),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  full_name VARCHAR(200),
  password_hash VARCHAR(60),
  phone_number VARCHAR(30) UNIQUE)
