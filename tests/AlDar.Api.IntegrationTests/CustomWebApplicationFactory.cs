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

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.UseSetting( 
                "Client:BaseUrl",
                "http://localhost:4200"
                );
        
        builder.ConfigureServices(services =>
        {
            var dbContextConfigurationDescriptor = services.SingleOrDefault(
                d => d.ServiceType ==
                    typeof( IDbContextOptionsConfiguration<AlDarDbContext>)
            );

            if (dbContextConfigurationDescriptor is not null)
            {
                services.Remove(dbContextConfigurationDescriptor);
            }

            services.AddSingleton<DbConnection>(_ =>
            {
                var connection =
                    new SqliteConnection("DataSource=:memory:");

                connection.Open();

                return connection;
            });

            services.AddDbContext<AlDarDbContext>(
                (serviceProvider, options) =>
                {
                    var connection =
                        serviceProvider
                            .GetRequiredService<DbConnection>();

                    options.UseSqlite(connection);
                });

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

        using var scope =
            host.Services.CreateScope();

        var dbContext =
            scope.ServiceProvider
                .GetRequiredService<AlDarDbContext>();

        dbContext.Database.EnsureCreated();

        IdentitySeeder
            .SeedRolesAsync(scope.ServiceProvider)
            .GetAwaiter()
            .GetResult();

        return host;
    }
}