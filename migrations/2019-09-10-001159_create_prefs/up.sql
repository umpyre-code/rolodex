CREATE TYPE email_notifications_pref AS ENUM (
  'never',
  'ral',
  'always'
);

CREATE TABLE prefs (
  id BIGSERIAL PRIMARY KEY,
  client_id BIGINT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  email_notifications EMAIL_NOTIFICATIONS_PREF NOT NULL DEFAULT 'ral'
);
