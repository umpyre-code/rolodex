CREATE TABLE users
(
    id INTEGER NOT NULL PRIMARY KEY,
    uuid UUID UNIQUE DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    name VARCHAR(100)
)
