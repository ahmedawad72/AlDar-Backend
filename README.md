# AlDar — الدار

**A modern learning platform built around the idea of belonging.**

AlDar (الدار, *The Home*) is an online learning platform designed to bring students, instructors, and educational content together in one accessible learning environment.

This repository contains the backend REST API, developed with **ASP.NET Core (.NET 10)** and designed with an emphasis on maintainability, security, separation of concerns, and automated testing.

**Status:** Active development · Backend foundation and authentication implemented

---

## Tech Stack

| Area             | Technologies                                 |
| ---------------- | -------------------------------------------- |
| Framework        | ASP.NET Core · .NET 10 · C#                  |
| Data Access      | Entity Framework Core · SQL Server           |
| Authentication   | ASP.NET Core Identity · JWT Bearer           |
| Email            | MailKit · SMTP                               |
| Logging & Errors | Serilog · ProblemDetails                     |
| Testing          | xUnit · Moq · WebApplicationFactory · SQLite |
| CI/CD            | GitHub Actions                               |

## Architecture

AlDar follows a **Clean Architecture-inspired layered design**, keeping application contracts and domain concerns separate from infrastructure implementations.

```text
AlDar-Backend/
├── src/
│   ├── AlDar.Api/
│   ├── AlDar.Application/
│   ├── AlDar.Domain/
│   └── AlDar.Infrastructure/
├── tests/
│   ├── AlDar.Infrastructure.Tests/
│   └── AlDar.Api.IntegrationTests/
├── .github/workflows/
└── AlDar.slnx
```

| Project            | Responsibility                                                 |
| ------------------ | -------------------------------------------------------------- |
| **API**            | HTTP endpoints, middleware, API configuration                  |
| **Application**    | Use-case contracts, DTOs, abstractions, application exceptions |
| **Domain**         | Core domain concepts, rules, and constants                     |
| **Infrastructure** | Persistence, Identity, JWT generation, email delivery          |

The architecture is intentionally lightweight, introducing abstractions and additional complexity only when justified by concrete requirements.

## Implemented Features

**Identity & Authentication**

- Student and instructor registration
- Email verification and confirmation resend
- Secure login with ASP.NET Core Identity
- JWT access tokens and bearer authentication
- Role support for Student, Teacher, and Admin
- Account lockout protection
- Authenticated current-user endpoint (`GET /api/auth/me`)

**API Infrastructure**

- EF Core persistence with SQL Server
- Centralized exception handling with ProblemDetails
- Structured request logging with Serilog
- Swagger/OpenAPI and CORS configuration
- Environment-based configuration and secret management

**Quality & Automation**

- Unit and HTTP integration tests
- SQLite in-memory database for integration testing
- Mocked external email delivery
- Automated build and test pipeline on pull requests
- Protected `main` branch with PR-based development

## Getting Started

### Prerequisites

- .NET 10 SDK
- SQL Server
- Git
- SMTP credentials for email delivery

### Local setup

**1. Clone the repository and restore dependencies**

```bash
git clone <repository-url>
cd AlDar-Backend
dotnet restore AlDar.slnx
```

**2. Configure development secrets**

Set the SQL Server connection string and JWT signing key using .NET User Secrets:

```bash
dotnet user-secrets set "ConnectionStrings:AlDarDb" "<connection-string>" --project src/AlDar.Api
dotnet user-secrets set "Jwt:SigningKey" "<strong-random-secret>" --project src/AlDar.Api
```

Configure SMTP credentials through the application's email configuration. Development JWT issuer, audience, and lifetime settings are defined in `appsettings.Development.json`.

Apply the database schema using the project's EF Core configuration before starting the application.

**3. Run the API**

```bash
dotnet run --project src/AlDar.Api
```

Swagger is available when running in the Development environment.

> **Security:** Never commit database passwords, SMTP credentials, signing keys, or other sensitive configuration values.

## Testing

The project includes unit and integration tests covering authentication behavior, identity workflows, HTTP responses, and JWT validation.

Integration tests run against an isolated ASP.NET Core test host using an SQLite in-memory database and a fake email service.

Run the full test suite:

```bash
dotnet test AlDar.slnx
```

### Continuous Integration

Every pull request targeting `main` triggers the GitHub Actions backend pipeline:

```text
Restore dependencies
        ↓
Build — Release
        ↓
Run automated tests
```

Merging requires the configured CI checks to pass.

## Roadmap

The next development phases will expand AlDar beyond authentication into its core learning experience:

- [ ] Course creation, management, and publishing
- [ ] Instructor ownership and authorization
- [ ] Course enrollment and learning content
- [ ] Quizzes and progress tracking
- [ ] Student and instructor dashboards
- [ ] Certificates and notifications
- [ ] Payments and course pricing

These features are planned and are not part of the current backend implementation.

---

**AlDar — A place to learn. A place to belong.**
