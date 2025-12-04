# Database Module (db/) --- Enterprise‑Grade FastAPI Architecture

This document explains **exactly how our database layer works**, how to
use it correctly, and the rules developers MUST follow when working with
SQLAlchemy ORM and asyncpg inside our FastAPI application.

It includes: - What each file does (`session.py` and `database.py`) -
When to use SQLAlchemy vs asyncpg - Recommended architecture - Best
practices for repositories & services - Warnings, rules, and performance
guidelines

This DB module is designed for **production, enterprise‑grade systems**.

------------------------------------------------------------------------

# 📁 Overview of db/ Module

    db/
      session.py       → SQLAlchemy ORM layer (AsyncSession)
      database.py      → asyncpg raw SQL layer (Connection Pool)
      models/          → SQLAlchemy ORM models
      repositories/    → ORM-based repository classes
      queries/         → Raw SQL query modules using asyncpg

We use **two parallel data layers**:

------------------------------------------------------------------------

# 1. `session.py` --- SQLAlchemy ORM Layer

### 🔍 Purpose

Provides: - `create_async_engine()` → SQLAlchemy async engine\
- `AsyncSessionLocal` → session factory\
- `Base` → declarative base for models\
- `get_session()` → FastAPI dependency to inject ORM sessions

This layer is used for: - ORM models\
- Relationships (1:N, M:N, cascading)\
- Auto-generated SQL\
- Alembic migrations\
- Typed entities & domain logic\
- Lazy/eager loading

### ✔️ When to Use SQLAlchemy ORM

Use ORM when: - You need models with relations\
- Your logic is domain-driven\
- Code readability and maintainability matter\
- You want DB-agnostic abstractions\
- You need automatic schema migrations (Alembic)

### ❌ When NOT to Use ORM

Avoid ORM for: - Very large datasets\
- Heavy analytics queries\
- Bulk inserts/updates\
- Postgres-specific operations\
- Performance-critical operations

------------------------------------------------------------------------

# 2. `database.py` --- asyncpg Raw SQL Layer

### 🔍 Purpose

Provides a direct **PostgreSQL connection pool** via asyncpg.

Includes: - `db.connect()` → create asyncpg pool\
- `db.disconnect()` → close pool\
- `db.transaction()` → managed transactions

### ✔️ When to Use asyncpg

Use asyncpg when: - You want **maximum performance** - You need **pure
SQL** with full control - Working with **millions of rows** - Running
analytical or reporting queries - Using PostgreSQL features like: -
`LISTEN / NOTIFY` - `COPY` (bulk import/export) - Stored
procedures/functions - Unlogged tables - RETURNING bulk operations

### ❌ When NOT to Use asyncpg

Do not use asyncpg for: - CRUD operations with relationships\
- Entity-based logic\
- Anything that already has ORM models

------------------------------------------------------------------------

# 🚨 VERY IMPORTANT --- DO NOT MIX BOTH IN THE SAME TRANSACTION

-   SQLAlchemy sessions and asyncpg connections are **isolated**.
-   Never:
    -   Start a SQLAlchemy transaction and use asyncpg inside it\
    -   Or vice versa

This leads to: - Double commits\
- Deadlocks\
- Inconsistent database state

**Each feature must choose exactly ONE data layer.**

------------------------------------------------------------------------

# 🧩 Recommended Architecture (Production Grade)

    app/
      db/
        session.py        # ORM session configuration
        database.py       # asyncpg pool
        models/
          user.py
          order.py
          ...
        repositories/
          user_repository.py
          order_repository.py
        queries/
          analytics_queries.py
          raw_user_queries.py

## ORM Repositories (repositories/)

Used for: - CRUD\
- Models with relationships\
- Business logic around entities

## Raw SQL Query Modules (queries/)

Used for: - Performance-heavy endpoints\
- Long-running queries\
- Aggregations, CTEs, analytical SQL

------------------------------------------------------------------------

# 🧠 Hybrid Strategy Used by Big Tech

Our architecture mirrors what large production systems do:

-   **95%** of API uses SQLAlchemy ORM\
-   **5%** uses asyncpg for ultra-fast SQL

This gives the best combination of: - Maintainability\
- Extensibility\
- High performance

------------------------------------------------------------------------

# 📘 Best Practices for Repositories & Services

## ✔️ 1. Repositories must NOT contain business logic

Repositories handle **persistence only**.

Good:

``` python
class UserRepository:
    async def get_by_id(self, session, id: int):
        return await session.get(User, id)
```

Bad:

``` python
# ❌ performs business decisions
if user.balance < order.amount:
    raise Exception("Insufficient funds")
```

------------------------------------------------------------------------

## ✔️ 2. Services handle business logic

Services orchestrate repositories.

Good:

``` python
class UserService:
    async def create_user(self, session, data):
        user = await self.user_repo.create(session, data)
        await session.commit()
        return user
```

------------------------------------------------------------------------

## ✔️ 3. Raw SQL modules should be stateless

Good:

``` python
async def get_top_users(limit=100):
    async with db.transaction() as conn:
        return await conn.fetch(
            "SELECT id, name, score FROM users ORDER BY score DESC LIMIT $1",
            limit
        )
```

------------------------------------------------------------------------

## ✔️ 4. NEVER let raw SQL and ORM share the same logic

If an endpoint uses ORM → stay ORM\
If an endpoint uses raw SQL → stay raw SQL

No hybrids inside the same use case.

------------------------------------------------------------------------

## ✔️ 5. Prefer ORM for write operations, asyncpg for reads

In most enterprise architectures: - Writes use ORM → ensures entity
integrity\
- Reads use asyncpg → optimized for fast response

------------------------------------------------------------------------

# Summary Table

  Task Type                      Use ORM   Use asyncpg
  ------------------------------ --------- -------------
  CRUD                           ✅        ❌
  Relationships                  ✅        ❌
  Bulk Inserts                   ❌        ✅
  Analytics                      ❌        ✅
  High performance queries       ❌        ✅
  Alembic migrations             ✅        ❌
  Domain modeling                ✅        ❌
  PostgreSQL-specific features   ❌        ✅

------------------------------------------------------------------------

# 📦 Final Notes for Developers

This module is designed to be: - **Scalable** - **High-performance** -
**Maintainable** - **Safe**

Follow the rules and separation-of-concerns strictly.

If you are unsure whether to use ORM or raw SQL:\
▶️ Default to **SQLAlchemy ORM** unless performance requires asyncpg.

------------------------------------------------------------------------

# 📝 Authoritative Rule

**Every feature must choose an ORM path or a raw SQL path. Never both.**

------------------------------------------------------------------------

# ✔️ You are now ready to work with the db/ module

Follow this architecture and your code will stay clean, scalable &
enterprise‑grade.
