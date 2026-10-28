using AlDar.Api.IntegrationTests.Fakes;
using AlDar.Application.Abstractions;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using System.Data.Common;

namespace AlDar.Api.IntegrationTests;

public class CustomWebApplicationFactory
    : WebApplicationFactory<Program>
{
    // A unique database for each factory instance.
    private readonly string _connectionString =
        new SqliteConnectionStringBuilder
        {
            DataSource = $"AlDarTests_{Guid.NewGuid():N}",
            Mode = SqliteOpenMode.Memory,
            Cache = SqliteCacheMode.Shared
        }.ToString();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.UseSetting(
            "Client:BaseUrl",
            "http://localhost:4200");

        builder.UseSetting(
            "Jwt:Issuer",
            "AlDar.Api.Tests");

        builder.UseSetting(
            "Jwt:Audience",
            "AlDar.Api.Tests");

        builder.UseSetting(
            "Jwt:ExpirationMinutes",
            "60");

        builder.UseSetting(
            "Jwt:SigningKey",
            "AlDar-Integration-Tests-Signing-Key-Only-Do-Not-Use-In-Production-2026!");

        builder.ConfigureServices(services =>
        {
            // Remove the production database configuration.
            services.RemoveAll<
                IDbContextOptionsConfiguration<AlDarDbContext>>();

            // Keep one connection open so the named
            // in-memory database stays alive.
            services.AddSingleton<DbConnection>(_ =>
            {
                var connection =
                    new SqliteConnection(_connectionString);

                connection.Open();

                return connection;
            });

            // IMPORTANT:
            // Each DbContext now uses its own connection,
            // but all connections share the same test database.
            services.AddDbContext<AlDarDbContext>(
                options => options.UseSqlite(_connectionString));

            // Replace email delivery with our test fake.
            services.RemoveAll<IEmailService>();

            services.AddSingleton<TestEmailService>();

            services.AddSingleton<IEmailService>(
                serviceProvider =>
                    serviceProvider
                        .GetRequiredService<TestEmailService>());
        });
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);

        using var scope = host.Services.CreateScope();

        // Open the keeper connection before database setup.
        // This keeps the named in-memory database alive.
        _ = scope.ServiceProvider
            .GetRequiredService<DbConnection>();

        var dbContext = scope.ServiceProvider
            .GetRequiredService<AlDarDbContext>();

        dbContext.Database.EnsureCreated();

        IdentitySeeder
            .SeedRolesAsync(scope.ServiceProvider)
            .GetAwaiter()
            .GetResult();

        return host;
    }
}