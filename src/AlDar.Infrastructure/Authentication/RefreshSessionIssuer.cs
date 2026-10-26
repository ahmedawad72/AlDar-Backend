using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Infrastructure.Persistence;
using Microsoft.Extensions.Options;

namespace AlDar.Infrastructure.Authentication;

public sealed class RefreshSessionIssuer(
    AlDarDbContext dbContext,
    IOptions<RefreshSessionOptions> options,
    TimeProvider timeProvider)
    : IRefreshSessionIssuer
{
    public async Task<CreatedRefreshSession> CreateAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var now = timeProvider.GetUtcNow().UtcDateTime;

        var absoluteExpiration = now.AddDays(options.Value.MaxSessionLifetimeDays);

        var tokenExpiration = now.AddDays(options.Value.TokenLifetimeDays);

        var expiresAt = tokenExpiration < absoluteExpiration
            ? tokenExpiration
            : absoluteExpiration;

        var rawToken = RefreshTokenSecurity.GenerateToken();

        var refreshToken = new RefreshToken
        {
            UserId = userId,
            FamilyId = Guid.NewGuid(),
            TokenHash = RefreshTokenSecurity.HashToken(rawToken),
            CreatedAtUtc = now,
            ExpiresAtUtc = expiresAt,
            AbsoluteExpiresAtUtc = absoluteExpiration
        };

        dbContext.RefreshTokens.Add(refreshToken);

        await dbContext.SaveChangesAsync(cancellationToken);

        return new CreatedRefreshSession(rawToken,expiresAt);
    }
}