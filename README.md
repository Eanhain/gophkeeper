# GophKeeper — Сервер

Серверная часть менеджера секретов GophKeeper.  
Хранит пароли, текстовые заметки, бинарные файлы и банковские карты в PostgreSQL.  
Чувствительные поля (пароли, PAN, тела заметок, бинарные данные) шифруются на уровне БД через `pgcrypto` (`pgp_sym_encrypt` / `pgp_sym_decrypt`).

## Архитектура

```
cmd/app/main.go          — точка входа
internal/
  app/                   — инициализация приложения и миграции
  controller/restapi/    — HTTP-роутер (Fiber), middleware, хендлеры v1
  usecase/               — бизнес-логика (auth, secrets, hash)
  repo/                  — интерфейсы репозиториев
  repo/persistent/       — реализации для PostgreSQL
  entity/                — доменные модели
domain/                  — общие интерфейсы (LoggerI) и sentinel-ошибки
config/                  — конфигурация из .env
pkg/                     — общие пакеты (postgres, httpserver, logger)
migrations/              — SQL-миграции (golang-migrate)
docs/                    — сгенерированная Swagger-документация
```

## Требования

- Go 1.25+
- PostgreSQL 15+ (с расширением `pgcrypto`)
- Docker (опционально, для поднятия БД)

## Быстрый старт

### 1. Поднять PostgreSQL

```bash
docker run -d \
  --name gophkeeper-db \
  -e POSTGRES_USER=db_user \
  -e POSTGRES_PASSWORD=s3cret \
  -e POSTGRES_DB=gophkeeper \
  -p 5432:5432 \
  postgres:15
```

### 2. Настроить .env

Скопировать `.env` в корень проекта (уже лежит) и при необходимости поменять значения:

```env
APP_NAME=gophkeeper
APP_VERSION=1.0.0
HTTP_PORT=8080
HTTP_USE_PREFORK_MODE=false
LOG_LEVEL=debug
PG_POOL_MAX=2
PG_URL=postgres://db_user:s3cret@localhost:5432/gophkeeper
CRYPTO_KEY=change-me
SWAGGER_ENABLED=true
```

**Важно:** `CRYPTO_KEY` — симметричный ключ, должен совпадать на клиенте и сервере.

### 3. Применить миграции

```bash
go run -tags migrate ./cmd/app
```

Для отката:

```bash
go run -tags migrate ./cmd/app -- --migrate-down
```

### 4. Запустить сервер

```bash
go run ./cmd/app
```

Сервер запустится на `http://localhost:8080`.

### 5. Swagger UI

При `SWAGGER_ENABLED=true` документация доступна по адресу:

```
http://localhost:8080/swagger/index.html
```

> **Примечание:** кнопка "Try it out" не работает, потому что все тела запросов/ответов шифруются AES-256-GCM. Swagger показывает структуру JSON до шифрования.

## Протокол шифрования

Все эндпоинты `/v1/*` проходят через `CryptoMiddleware`:

1. **Запрос (клиент → сервер):**
   - Клиент сериализует JSON, шифрует AES-256-GCM (ключ = `SHA-256(CRYPTO_KEY)`).
   - Отправляет `nonce (12 байт) || ciphertext` с `Content-Type: application/octet-stream`.

2. **Ответ (сервер → клиент):**
   - Сервер формирует JSON, middleware шифрует его тем же способом.
   - Клиент расшифровывает и получает JSON.

**Без шифрования API использовать нельзя** — middleware вернёт HTTP 400.

## API эндпоинты

| Метод  | Путь                                       | Описание                    | Авторизация |
|--------|--------------------------------------------|-----------------------------|-------------|
| POST   | `/v1/api/user/register`                    | Регистрация                 | —           |
| POST   | `/v1/api/user/login`                       | Логин, возвращает JWT       | —           |
| DELETE | `/v1/api/user/delete-user`                 | Удалить аккаунт             | JWT         |
| POST   | `/v1/api/user/secret/post-login-password`  | Создать логин/пароль        | JWT         |
| POST   | `/v1/api/user/secret/post-text-secret`     | Создать текстовую заметку   | JWT         |
| POST   | `/v1/api/user/secret/post-binary-secret`   | Создать бинарный секрет     | JWT         |
| POST   | `/v1/api/user/secret/post-card-secret`     | Создать карту               | JWT         |
| GET    | `/v1/api/user/secret/get-login-password`   | Получить логины/пароли      | JWT         |
| GET    | `/v1/api/user/secret/get-text-secret`      | Получить текстовые заметки  | JWT         |
| GET    | `/v1/api/user/secret/get-binary-secret`    | Получить бинарные секреты   | JWT         |
| GET    | `/v1/api/user/secret/get-card-secret`      | Получить карты              | JWT         |
| GET    | `/v1/api/user/secret/get-all-secrets`      | Получить все секреты        | JWT         |
| DELETE | `/v1/api/user/secret/delete-login-password`| Удалить логин/пароль        | JWT         |
| DELETE | `/v1/api/user/secret/delete-text-secret`   | Удалить текстовую заметку   | JWT         |
| DELETE | `/v1/api/user/secret/delete-binary-secret` | Удалить бинарный секрет     | JWT         |
| DELETE | `/v1/api/user/secret/delete-card-secret`   | Удалить карту               | JWT         |

## Тесты

```bash
go test ./...
```

Покрытие по ключевым пакетам:
- `internal/usecase/auth` — 100%
- `internal/usecase/secrets` — 92%+
- `internal/controller/restapi/v1` — 85%+
- `internal/controller/restapi/middleware` — 93%+

## Перегенерация Swagger

После изменения аннотаций в хендлерах:

```bash
go tool swag init -g internal/controller/restapi/router.go
```

## Структура БД

```
users              — пользователи (username, password_hash)
user_credentials   — логины/пароли (password_enc — pgcrypto)
user_text_items    — текстовые заметки (body — pgcrypto)
user_binary_items  — бинарные данные (data — pgcrypto)
user_cards         — банковские карты (pan_enc — pgcrypto)
```

Все секреты привязаны к пользователю через `user_id` с `ON DELETE CASCADE`.
