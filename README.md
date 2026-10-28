# AlDar — Backend API

AlDar is an application being developed with an **ASP.NET Core (.NET 10)** backend and an **Angular** client. The backend follows a layered architecture and provides account registration, email verification, JWT authentication, and refresh-token-based session management.

> **Project status:** Backend authentication and its automated tests are implemented. Angular integration, deployment configuration, and production-database concurrency verification are still in progress. This README describes the current backend design, not a production-readiness certification.

## Technology stack

- **.NET 10 / ASP.NET Core Web API**
- **Entity Framework Core** with **SQL Server** for the application database
- **ASP.NET Core Identity** for users, roles, passwords, email confirmation, and lockout
- **JWT bearer authentication** for protected API requests
- **Rotating refresh tokens** persisted as hashes
- **xUnit, Moq, and SQLite in-memory** for automated tests
- **Angular** client (integration in progress)

## Solution structure

```text
AlDar.slnx
src/
  AlDar.Api/                 # HTTP controllers, middleware, configuration
  AlDar.Application/         # Contracts, DTOs, application abstractions
  AlDar.Domain/              # Domain concepts and constants
  AlDar.Infrastructure/      # Identity, EF Core, persistence, auth implementations
tests/
  AlDar.Api.IntegrationTests/ # End-to-end HTTP behavior against a test host
  AlDar.Infrastructure.UnitTests/ # Application/infrastructure behavior tests
```

## Authentication API

All routes below are relative to the API host.

| Method | Endpoint | Purpose | Authentication / CSRF |
|---|---|---|---|
| `POST` | `/api/auth/register` | Register a new account | Public |
| `POST` | `/api/auth/confirm-email` | Confirm an account's email address | Public |
| `POST` | `/api/auth/resend-confirmation-email` | Request another confirmation message | Public |
| `GET` | `/api/auth/csrf` | Obtain the antiforgery request token and its cookie | Public |
| `POST` | `/api/auth/login` | Validate credentials, issue JWT, create refresh session | Public; CSRF required |
| `POST` | `/api/auth/refresh` | Rotate refresh session and obtain a fresh JWT | Refresh cookie; CSRF required |
| `POST` | `/api/auth/logout` | Revoke the current refresh-token family and clear cookie | Refresh cookie if present; CSRF required |
| `GET` | `/api/auth/me` | Return the current user's ID, email, and roles | Bearer JWT required |

### Login and refresh responses

Successful login and refresh responses include an access token, its expiration, and user information (including ID, email, display name, and roles). **Raw refresh tokens are never returned in the JSON body.**

### Cookie-based refresh sessions

The API issues a refresh-token cookie named `aldar.refresh` with these attributes:

| Attribute | Setting |
|---|---|
| `HttpOnly` | `true` |
| `Secure` | `true` |
| `SameSite` | `Strict` |
| `Path` | `/api/auth` |
| `Expires` | Corresponds to the session expiration |

Refresh tokens are cryptographically generated; the database stores **token hashes**, not plaintext credentials. Successful refresh requests consume the previous token and issue a replacement in the same token family. Token families have an absolute lifetime in addition to each token's expiration.

Logout revokes the refresh-token family associated with the supplied cookie. Previously issued **access JWTs remain valid until they expire**; logout prevents the affected session from obtaining new JWTs.

### CSRF protection

`POST /api/auth/login`, `POST /api/auth/refresh`, and `POST /api/auth/logout` use ASP.NET Core antiforgery validation.

For browser clients:

1. Call `GET /api/auth/csrf` with credentials enabled.
2. Read the `token` field from the JSON response; the API also sets the `aldar.csrf` cookie.
3. Include both the cookie and the `X-CSRF-TOKEN` header with the returned request token when calling the protected authentication POST endpoints.
4. Include credentials on cross-origin authentication requests so the browser can send and receive the cookies.

An invalid or missing CSRF token is rejected before the protected action runs. A valid CSRF token does **not** replace password or refresh-token validation.

> **Browser deployment constraint:** `Secure` and `SameSite=Strict` cookies require the frontend/API site and HTTPS setup to be tested together. The current development CORS origin has been `http://localhost:4200`; verify the actual frontend/API schemes and domains before relying on cookie-based refresh in a browser. CORS is not a substitute for CSRF validation.

## Running locally

Requirements:

- **.NET 10 SDK**
- A configured **SQL Server** instance for normal API execution
- Required development settings and secrets for the database connection, JWT signing, and email delivery

From the repository root:

```powershell
dotnet restore AlDar.slnx
dotnet build AlDar.slnx
dotnet run --project src/AlDar.Api
```

Review the API's configuration files and development secrets for the exact connection string, JWT, and email setting names; do not commit production credentials or signing keys to the repository.

## Automated tests

Run all projects in the solution:

```powershell
dotnet test AlDar.slnx
```

Or test projects individually:

```powershell
dotnet test tests/AlDar.Infrastructure.UnitTests/AlDar.Infrastructure.UnitTests.csproj
dotnet test tests/AlDar.Api.IntegrationTests/AlDar.Api.IntegrationTests.csproj
```

The integration tests use a test host with an **SQLite in-memory** database. They cover login and email confirmation, cookie issuance, refresh-token rotation and replay handling, logout and session revocation, CSRF enforcement, and concurrency scenarios.

**Important:** Passing SQLite concurrency tests does not prove equivalent behavior on SQL Server; SQL Server transaction/locking behavior must be tested separately before production deployment.

## Remaining verification before deployment

- [ ] Confirm all solution tests pass and CI is green.
- [ ] Reproduce concurrent refresh and logout-versus-refresh scenarios using SQL Server.
- [ ] Confirm HTTPS, cookie attributes, CSRF headers, and CORS allowlist using a real browser and the actual Angular origin.
- [ ] Keep secrets in secure configuration, not the repository.
- [ ] Confirm application startup and EF Core migrations against the intended deployment database.

## Frontend integration

The Angular client will use the JWT access token for API authorization and credentialed authentication calls for refresh and logout. Because the refresh token is `HttpOnly`, browser JavaScript must not read or persist it directly. The client needs to obtain an antiforgery request token for protected auth POST requests and restore sessions through the refresh endpoint when appropriate.
