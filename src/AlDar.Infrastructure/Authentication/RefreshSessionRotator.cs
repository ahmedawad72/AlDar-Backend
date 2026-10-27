using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AlDar.Infrastructure.Authentication;

public sealed class RefreshSessionRotator(
    AlDarDbContext dbContext,
    IOptions<RefreshSessionOptions> options,
    TimeProvider timeProvider)
    : IRefreshSessionRotator
{
    public async Task<RotatedRefreshSession?> RotateAsync(string rawToken,CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return null;

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var tokenHash = RefreshTokenSecurity.HashToken(rawToken);

        var currentToken = await dbContext.RefreshTokens
            .AsNoTracking()
            .SingleOrDefaultAsync(
                x => x.TokenHash == tokenHash,
                cancellationToken);

        // Unknown token
        if (currentToken is null)
            return null;

        // Reuse of a previously consumed token
        if (currentToken.ConsumedAtUtc is not null)
        {
            await RevokeFamilyAsync(currentToken.FamilyId, now, cancellationToken);

            return null;
        }

        // Revoked or expired token
        if (currentToken.RevokedAtUtc is not null ||
            currentToken.ExpiresAtUtc <= now ||
            currentToken.AbsoluteExpiresAtUtc <= now)
        {
            return null;
        }

        await using var transaction =
            await dbContext.Database.BeginTransactionAsync(cancellationToken);

        // Atomically claim the old token.
        var affectedRows = await dbContext.RefreshTokens
            .Where(x =>
                x.Id == currentToken.Id &&
                x.ConsumedAtUtc == null &&
                x.RevokedAtUtc == null &&
                x.ExpiresAtUtc > now &&
                x.AbsoluteExpiresAtUtc > now)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    x => x.ConsumedAtUtc,
                    (DateTime?)now),
                cancellationToken);

        if (affectedRows != 1)
        {
            await transaction.RollbackAsync(cancellationToken);

            // The token may have been consumed by another request.
            await RevokeFamilyAsync(currentToken.FamilyId,now,cancellationToken);

            return null;
        }

        var newRawToken = RefreshTokenSecurity.GenerateToken();

        var newExpiration =
            now.AddDays(options.Value.TokenLifetimeDays);

        // Never extend the absolute session lifetime.
        if (newExpiration > currentToken.AbsoluteExpiresAtUtc)
        {
            newExpiration = currentToken.AbsoluteExpiresAtUtc;
        }

        var replacement = new RefreshToken
        {
            UserId = currentToken.UserId,
            FamilyId = currentToken.FamilyId,
            TokenHash = RefreshTokenSecurity.HashToken(newRawToken),
            CreatedAtUtc = now,
            ExpiresAtUtc = newExpiration,
            AbsoluteExpiresAtUtc = currentToken.AbsoluteExpiresAtUtc
        };

        dbContext.RefreshTokens.Add(replacement);

        await dbContext.SaveChangesAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return new RotatedRefreshSession(
            currentToken.UserId,
            new CreatedRefreshSession(newRawToken,newExpiration));
    }

    private async Task RevokeFamilyAsync(Guid familyId,DateTime now,CancellationToken cancellationToken)
    {
        await dbContext.RefreshTokens
            .Where(x =>
                x.FamilyId == familyId &&
                x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(
                    x => x.RevokedAtUtc,
                    (DateTime?)now),
                cancellationToken);
    }
}