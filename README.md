# AlDar — الدار

AlDar is an online learning platform designed to provide students,
teachers, and administrators with a structured learning environment.

This repository contains the backend API for the AlDar platform.

## Tech Stack

- ASP.NET Core
- C#
- Entity Framework Core
- SQL Server
- ASP.NET Core Identity
- xUnit
- SQLite for integration testing
- Serilog
- Swagger / OpenAPI

## Architecture

The backend follows a layered architecture:

- **Domain** — business concepts, rules, and constants
- **Application** — use cases, contracts, DTOs, and application exceptions
- **Infrastructure** — EF Core, Identity, email, and external integrations
- **API** — HTTP endpoints and application pipeline

## Current Features

- User registration
- Student and teacher roles
- Email confirmation
- Resend confirmation email
- Global exception handling
- ProblemDetails responses
- Structured logging
- Unit testing
- Integration testing

## Planned Features

- Login and JWT authentication
- Role-based authorization
- Course management
- Enrollment workflow
- Lessons and learning progress
- Quizzes
- Notifications
- Certificates

## Project Structure

```text
src/
├── AlDar.Api/
├── AlDar.Application/
├── AlDar.Domain/
└── AlDar.Infrastructure/

tests/
├── AlDar.Infrastructure.Tests/
└── AlDar.Api.IntegrationTests/