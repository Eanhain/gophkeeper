-- Владелец (учётка для входа в систему)
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,            -- без UNIQUE
  created_at    TIMESTAMPTZ DEFAULT now()
);

-- Пары логин/пароль (много записей на пользователя)
CREATE TABLE IF NOT EXISTS user_credentials (
  id           SERIAL PRIMARY KEY,
  user_id      INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  login        TEXT NOT NULL,
  password_enc BYTEA NOT NULL,            -- зашифрованный пароль
  label        TEXT,                      -- название/метка сервиса
  created_at   TIMESTAMPTZ DEFAULT now()
);

-- Произвольные текстовые данные
CREATE TABLE IF NOT EXISTS user_text_items (
  id         SERIAL PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT,
  body       TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Произвольные бинарные данные
CREATE TABLE IF NOT EXISTS user_binary_items (
  id         SERIAL PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename   TEXT,
  mime_type  TEXT,
  data       BYTEA NOT NULL,              -- бинарные данные
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Данные банковских карт
CREATE TABLE IF NOT EXISTS user_cards (
  id           SERIAL PRIMARY KEY,
  user_id      INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cardholder   TEXT,
  pan_enc      BYTEA NOT NULL,            -- зашифрованный PAN
  exp_month    SMALLINT NOT NULL CHECK (exp_month BETWEEN 1 AND 12),
  exp_year     SMALLINT NOT NULL,
  brand        TEXT,
  last4        CHAR(4),
  created_at   TIMESTAMPTZ DEFAULT now()
);