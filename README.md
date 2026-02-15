# GophKeeper — Сервер

Серверная часть менеджера секретов GophKeeper.  
Хранит пароли, текстовые заметки, бинарные файлы и банковские карты в PostgreSQL.  
Чувствительные поля шифруются на уровне приложения (AES-256-GCM) индивидуальным ключом для каждого пользователя, который выводится из пароля через Argon2id.

**Все соединения защищены обязательным TLS** — сервер не запустится без сертификатов, что гарантирует защиту JWT-токенов и данных при передаче.

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
pkg/
  crypto/                — AES-256-GCM шифрование, Argon2id KDF
  postgres/              — обёртка над pgxpool
  httpserver/            — обёртка над Fiber (HTTPS с обязательным TLS)
  logger/                — структурированный логгер
migrations/              — SQL-миграции (golang-migrate)
docs/                    — сгенерированная Swagger-документация
```

## Требования

- Go 1.25+
- PostgreSQL 15+
- Docker (опционально, для поднятия БД)
- TLS-сертификат и приватный ключ (см. ниже)

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

### 2. Сгенерировать TLS-сертификаты

Для разработки можно использовать self-signed сертификат:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 -nodes \
  -subj '/CN=localhost'
```

Для продакшена используйте сертификаты от CA (Let's Encrypt и т.д.).

### 3. Настроить .env

Скопировать `.env` в корень проекта и при необходимости поменять значения:

```env
APP_NAME=gophkeeper
APP_VERSION=1.0.0
HTTP_PORT=8080
HTTP_USE_PREFORK_MODE=false
LOG_LEVEL=debug
PG_POOL_MAX=2
PG_URL=postgres://db_user:s3cret@localhost:5432/gophkeeper
JWT_SECRET=your-strong-secret-here
TLS_CERT_FILE=./certs/cert.pem
TLS_KEY_FILE=./certs/key.pem
SWAGGER_ENABLED=true
```

**Обязательные переменные (без дефолтов — fail early):**

| Переменная      | Описание                          |
|-----------------|-----------------------------------|
| `JWT_SECRET`    | Секрет для подписи JWT-токенов    |
| `TLS_CERT_FILE` | Путь к TLS-сертификату (PEM)      |
| `TLS_KEY_FILE`  | Путь к приватному ключу TLS (PEM) |

Если любая из них не задана — сервер не запустится.

### 4. Применить миграции

```bash
go run -tags migrate ./cmd/app
```

### 5. Запустить сервер

```bash
go run ./cmd/app
```

Сервер запустится на `https://localhost:8080` (HTTPS).

### 6. Swagger UI

При `SWAGGER_ENABLED=true` документация доступна по адресу:

```
https://localhost:8080/swagger/index.html
```

> При использовании self-signed сертификата браузер покажет предупреждение — его можно пропустить.

## Схема шифрования

### Транспортная безопасность (TLS)

Сервер принимает **только HTTPS-подключения**. TLS — обязательный, без сертификатов сервер не стартует. Это гарантирует:

- JWT-токены невозможно перехватить без TLS
- Все данные (headers, body, cookies) шифруются на транспортном уровне
- Стандартный подход, поддерживаемый всеми HTTP-клиентами и прокси

### Шифрование данных at rest (AES-256-GCM)

Выполняется **индивидуально для каждого пользователя**:

1. При регистрации генерируется случайный 16-байтовый `crypto_salt` и сохраняется в таблицу `users`.
2. При логине из пароля пользователя и его `crypto_salt` через **Argon2id** выводится 256-битный ключ шифрования.
3. Этот ключ передаётся в JWT-токене (claim `crypto_key`) и используется при каждом запросе для шифрования/расшифровки чувствительных полей.
4. Шифрование — **AES-256-GCM** на уровне приложения (в Go-коде), а не в БД.

## API эндпоинты

| Метод  | Путь                                       | Описание                    | Авторизация |
|--------|--------------------------------------------|-----------------------------|-------------|
| POST   | `/v1/api/user/register`                    | Регистрация, возвращает JWT | —           |
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
- `pkg/crypto` — шифрование, KDF, round-trip
- `internal/usecase/auth` — регистрация, аутентификация, crypto key derivation
- `internal/usecase/secrets` — CRUD секретов с per-user ключом
- `internal/controller/restapi/v1` — API-хендлеры (моки + httptest)
- `internal/controller/restapi/middleware` — recovery middleware

## Перегенерация Swagger

После изменения аннотаций в хендлерах:

```bash
swag init -g internal/controller/restapi/router.go -o docs --parseDependency --parseInternal
```

## Структура БД

```
users              — пользователи (username, password_hash, crypto_salt)
user_credentials   — логины/пароли (password_enc — AES-256-GCM BYTEA)
user_text_items    — текстовые заметки (body — AES-256-GCM BYTEA)
user_binary_items  — бинарные данные (data — AES-256-GCM BYTEA)
user_cards         — банковские карты (pan_enc — AES-256-GCM BYTEA)
```

- Первичные ключи — `INT GENERATED ALWAYS AS IDENTITY` (IDENTITY вместо SERIAL).
- Строковые колонки — `VARCHAR(n)` с ограничением длины.
- Все секреты привязаны к пользователю через `user_id` с `ON DELETE CASCADE`.
- Расширение `pgcrypto` **не требуется** — шифрование выполняется на уровне приложения.
