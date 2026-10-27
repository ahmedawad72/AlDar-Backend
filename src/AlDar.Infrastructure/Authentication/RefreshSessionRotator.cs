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
    public async Task<string?> InspectAsync(string rawToken,CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return null;

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var tokenHash = RefreshTokenSecurity.HashToken(rawToken);

        var session = await dbContext.RefreshTokens
            .AsNoTracking()
            .SingleOrDefaultAsync(
                x => x.TokenHash == tokenHash,
                cancellationToken);

        if (session is null)
            return null;

        // Detect reuse of a previously consumed token.
        if (session.ConsumedAtUtc is not null)
        {
            await RevokeFamilyAsync(
                session.FamilyId,
                now,
                cancellationToken);

            return null;
        }

        // Reject revoked or expired tokens.
        if (session.RevokedAtUtc is not null ||
            session.ExpiresAtUtc <= now ||
            session.AbsoluteExpiresAtUtc <= now)
        {
            return null;
        }

        return session.UserId;
    }

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

        if (currentToken is null)
            return null;

        // Reusing a consumed token indicates possible replay.
        if (currentToken.ConsumedAtUtc is not null)
        {
            await RevokeFamilyAsync(currentToken.FamilyId, now,cancellationToken);

            return null;
        }

        // Reject revoked or expired tokens.
        if (currentToken.RevokedAtUtc is not null ||
            currentToken.ExpiresAtUtc <= now ||
            currentToken.AbsoluteExpiresAtUtc <= now)
        {
            return null;
        }

        await using var transaction =
            await dbContext.Database.BeginTransactionAsync(cancellationToken);

        // Atomically consume the old token.
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

            // Distinguish replay from other validation failures.
            var wasConsumed = await dbContext.RefreshTokens
                .AsNoTracking()
                .Where(x => x.Id == currentToken.Id)
                .Select(x => x.ConsumedAtUtc != null)
                .SingleOrDefaultAsync(cancellationToken);

            if (wasConsumed)
            {
                await RevokeFamilyAsync(
                    currentToken.FamilyId,
                    now,
                    cancellationToken);
            }

            return null;
        }

        // Generate the replacement refresh token.
        var newRawToken = RefreshTokenSecurity.GenerateToken();

        var newExpiration =
            now.AddDays(options.Value.TokenLifetimeDays);

        // Never extend beyond the absolute session lifetime.
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