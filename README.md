# ANAHP Data Sync Service

A production-ready FastAPI microservice that connects to an existing MSSQL database, extracts and transforms data, sends it to the external SINHA API, and logs each operation. The service is secure, scalable, testable, and designed for containerized deployment.

## 🏛️ Architecture

This project follows the principles of **Clean Architecture** to ensure a separation of concerns, making the application more maintainable, scalable, and testable.

-   **`main.py`**: The application entrypoint that ties everything together.
-   **`core`**: Contains application-wide logic like configuration management (`config.py`), database session handling (`database.py`), and authentication (`auth.py`).
-   **`routers`**: Defines the API endpoints. This layer is responsible for handling HTTP requests and responses, delegating the business logic to the service layer.
-   **`services`**: Contains the core business logic. It orchestrates the flow of data, calling repositories to interact with the database and clients to interact with external services.
-   **`repositories`**: The data access layer. It abstracts all database interactions using SQLAlchemy, providing a clean interface to the service layer.
-   **`models`**: Defines the SQLAlchemy ORM models, representing the database tables.
-   **`schemas`**: Defines the Pydantic models used for data validation, serialization, and API documentation (request/response bodies).

The entire application is built on an asynchronous stack (`asyncio`, `FastAPI`, `SQLAlchemy[asyncio]`, `HTTPX`) for high performance.

## ✨ Features

-   **Timestamp-based Polling**: Periodically checks the source database for new or updated records based on an `updated_at` timestamp.
-   **Asynchronous Data Synchronization**: Uses FastAPI's `BackgroundTasks` to process data synchronization without blocking the API response, making it suitable for long-running tasks.
-   **Robust External API Integration**: Communicates with the external SINHA API using `HTTPX`. Includes an automatic retry mechanism (with exponential backoff) for transient network or server errors.
-   **Client-Side Idempotency**: Prevents duplicate data submission by checking the `operations_log` table before sending a batch, ensuring that each batch (`id_lote`) is processed only once successfully.
-   **Comprehensive Operational Logging**: Every sync attempt (both successful and failed) is recorded in the `operations_log` table, providing a full audit trail.
-   **Secure by Default**: Endpoints are protected using OAuth2 Password Flow and JWTs. Passwords are never stored in plain text.
-   **Configuration-Driven**: All critical settings (database URLs, API keys, secrets) are managed via environment variables for security and flexibility across different environments (dev, staging, prod).

## 🛠️ Technology Stack

-   **Framework**: FastAPI
-   **ORM**: SQLAlchemy 2.0 (with `asyncio` support)
-   **Data Validation**: Pydantic V2
-   **Async HTTP Client**: HTTPX
-   **Retry Logic**: Tenacity
-   **Authentication**: PyJWT, Passlib (for password hashing)
-   **Server**: Uvicorn
-   **Containerization**: Docker & Docker Compose

## 🚀 Getting Started

### Prerequisites

-   Docker
-   Docker Compose

### 1. Configuration

First, create a `.env` file in the project root by copying the example file:

```bash
cp .env.example .env
```

Now, open the `.env` file and fill in the required values.

### 2. Running the Application

With Docker and Docker Compose installed, you can build and run the application with a single command:

```bash
docker-compose up --build
```

The API will be available at `http://localhost:8000`.
The interactive API documentation (Swagger UI) will be at `http://localhost:8000/api/v1/docs`.

## ⚙️ API Usage

### 1. Obtain an Access Token

To interact with the secure endpoints, you first need to get a JWT. The default user is `anaph_user` with password `secretpassword`.

```bash
curl -X POST "http://localhost:8000/api/v1/token" \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=anaph_user&password=secretpassword"
```

The response will look like this:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### 2. Trigger Data Synchronization

Use the `access_token` from the previous step as a Bearer token to call the `/sync` endpoint.

```bash
# Replace YOUR_TOKEN_HERE with the access_token
TOKEN="YOUR_TOKEN_HERE"

curl -X POST "http://localhost:8000/api/v1/sync" \
-H "Authorization: Bearer $TOKEN"
```

You will receive an immediate `202 Accepted` response, indicating that the process has started in the background.

```json
{
  "message": "Data synchronization process has been started in the background."
}
```

## 📝 Environment Variables

The following environment variables are used for configuration:

| Variable                      | Description                                                                                             | Example                                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `DATABASE_URL`                | **Required**. The connection string for the MSSQL database.                                             | `mssql+pyodbc://user:password@host/database?driver=ODBC+Driver+17+for+SQL+Server`          |
| `SINHA_API_URL`               | The base URL for the external SINHA API.                                                                | `http://sinha-env-homologacao.sa-east-1.elasticbeanstalk.com/api`                          |
| `SINHA_API_USER`              | **Required**. The username for Basic Authentication with the SINHA API.                                 | `sinha_user`                                                                               |
| `SINHA_API_PASSWORD`          | **Required**. The password for Basic Authentication with the SINHA API.                                 | `sinha_password`                                                                           |
| `SECRET_KEY`                  | **Required**. A secret key for signing JWTs. Generate one with `openssl rand -hex 32`.                  | `09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7`                         |
| `ALGORITHM`                   | The algorithm used for JWT encoding.                                                                    | `HS256`                                                                                    |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | The lifetime of an access token in minutes.                                                             | `30`                                                                                       |
| `LAST_SYNC_TIMESTAMP_FILE`    | The file path to store the timestamp of the last successful sync. Must be a persistent volume in Docker. | `/var/data/last_sync_timestamp.txt`                                                        |

## 📁 Project Structure

```
app/
├── core/            # Config, database, auth, logging
├── models/          # SQLAlchemy models
├── schemas/         # Pydantic models (request/response)
├── routers/         # FastAPI route definitions
├── services/        # Business logic
├── repositories/    # DB access layer
├── main.py          # Entrypoint
.env.example         # Example environment variables
Dockerfile           # Instructions to build the app container
docker-compose.yml   # Docker Compose configuration (if used)
README.md            # This file
```