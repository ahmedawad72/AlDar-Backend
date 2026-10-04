using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Infrastructure.Email;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AlDar.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.AddDbContext<AlDarDbContext>(options =>
            options.UseSqlServer(config.GetConnectionString("AlDarDb")));

        services.AddIdentity<AppUser, IdentityRole>(options =>
        {
            options.SignIn.RequireConfirmedEmail = true;
        })
        .AddEntityFrameworkStores<AlDarDbContext>()
        .AddDefaultTokenProviders();

        services.AddScoped<IAuthService, AuthService>();
       
        services.Configure<EmailOptions>(
            config.GetSection(EmailOptions.SectionName));

        services.AddSingleton<IEmailService, SmtpEmailService>();

        return services;
    }
}