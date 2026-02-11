-- Владелец (учётка для входа в систему)
CREATE TABLE IF NOT EXISTS users (
  id            INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username      VARCHAR(128) NOT NULL UNIQUE,
  password_hash VARCHAR(512) NOT NULL,
  crypto_salt   BYTEA NOT NULL,               -- per-user salt for Argon2 encryption key derivation
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- Пары логин/пароль (много записей на пользователя)
CREATE TABLE IF NOT EXISTS user_credentials (
  id           INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  login        VARCHAR(256) NOT NULL,
  password_enc BYTEA NOT NULL,                -- AES-256-GCM encrypted password
  label        VARCHAR(256),                  -- название/метка сервиса
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- Произвольные текстовые данные
CREATE TABLE IF NOT EXISTS user_text_items (
  id         INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      VARCHAR(256),
  body       BYTEA NOT NULL,                  -- AES-256-GCM encrypted text
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Произвольные бинарные данные
CREATE TABLE IF NOT EXISTS user_binary_items (
  id         INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename   VARCHAR(512),
  mime_type  VARCHAR(128),
  data       BYTEA NOT NULL,                  -- AES-256-GCM encrypted binary data
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Данные банковских карт
CREATE TABLE IF NOT EXISTS user_cards (
  id           INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cardholder   VARCHAR(256),
  pan_enc      BYTEA NOT NULL,                -- AES-256-GCM encrypted PAN
  exp_month    SMALLINT NOT NULL CHECK (exp_month BETWEEN 1 AND 12),
  exp_year     SMALLINT NOT NULL,
  brand        VARCHAR(64),
  last4        CHAR(4),
  created_at   TIMESTAMPTZ DEFAULT now()
);
