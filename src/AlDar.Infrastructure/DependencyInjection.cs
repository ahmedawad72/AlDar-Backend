using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Infrastructure.Authentication;
using AlDar.Infrastructure.Email;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AlDar.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration config)
    {
        // Database
        services.AddDbContext<AlDarDbContext>(options =>
            options.UseSqlServer(config.GetConnectionString("AlDarDb")));

        // Identity
        services
            .AddIdentity<AppUser, IdentityRole>(options =>
            {
                options.SignIn.RequireConfirmedEmail = true;

                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan =
                    TimeSpan.FromMinutes(15);
            })
            .AddEntityFrameworkStores<AlDarDbContext>()
            .AddDefaultTokenProviders();

        // Application services
        services.AddScoped<IAuthService, AuthService>();

        // Email
        services.Configure<EmailOptions>(
            config.GetSection(
                EmailOptions.SectionName));

        services.AddSingleton<
            IEmailService,
            SmtpEmailService>();

        // JWT configuration
        services.Configure<JwtOptions>(
            config.GetSection(JwtOptions.SectionName));

        var jwtOptions =
            config
                .GetSection(JwtOptions.SectionName)
                .Get<JwtOptions>()
            ?? throw new InvalidOperationException(
                "JWT configuration is missing.");

        ValidateJwtOptions(jwtOptions);

        services.AddSingleton<IJwtTokenGenerator,JwtTokenGenerator>();

        // Authentication
        services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme =
                    JwtBearerDefaults.AuthenticationScheme;

                options.DefaultChallengeScheme =
                    JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;

                options.TokenValidationParameters =
                    new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer =
                            jwtOptions.Issuer,

                        ValidateAudience = true,
                        ValidAudience =
                            jwtOptions.Audience,

                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey =
                            new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes(
                                    jwtOptions.SigningKey)),

                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,

                        NameClaimType =
                            JwtRegisteredClaimNames.Sub,

                        RoleClaimType =
                            ClaimTypes.Role
                    };
            });

        // Authorization
        services.AddAuthorization();

        return services;
    }

    private static void ValidateJwtOptions( JwtOptions options)
    {
        if (string.IsNullOrWhiteSpace(
            options.Issuer))
        {
            throw new InvalidOperationException(
                "JWT issuer is not configured.");
        }

        if (string.IsNullOrWhiteSpace(
            options.Audience))
        {
            throw new InvalidOperationException(
                "JWT audience is not configured.");
        }

        if (string.IsNullOrWhiteSpace(
            options.SigningKey))
        {
            throw new InvalidOperationException(
                "JWT signing key is not configured.");
        }

        if (options.ExpirationMinutes <= 0)
        {
            throw new InvalidOperationException(
                "JWT expiration must be greater than zero.");
        }
    }
}