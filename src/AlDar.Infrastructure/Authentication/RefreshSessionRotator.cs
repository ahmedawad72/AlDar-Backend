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
    private static readonly TimeSpan DuplicateWindow =
        TimeSpan.FromSeconds(5);

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

        if (session is null || session.RevokedAtUtc is not null)
            return null;

        if (session.ConsumedAtUtc is not null)
        {
            await HandleConsumedTokenAsync(
                session,
                cancellationToken);

            return null;
        }

        if (session.ExpiresAtUtc <= now ||
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

        if (currentToken is null ||
            currentToken.RevokedAtUtc is not null)
        {
            return null;
        }

        if (currentToken.ConsumedAtUtc is not null)
        {
            await HandleConsumedTokenAsync(currentToken,cancellationToken);

            return null;
        }

        if (currentToken.ExpiresAtUtc <= now ||
            currentToken.AbsoluteExpiresAtUtc <= now)
        {
            return null;
        }

        await using var transaction =
            await dbContext.Database.BeginTransactionAsync(cancellationToken);

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

            var latestState = await dbContext.RefreshTokens
                .AsNoTracking()
                .SingleOrDefaultAsync(
                    x => x.Id == currentToken.Id,
                    cancellationToken);

            if (latestState is not null &&
                latestState.RevokedAtUtc is null &&
                latestState.ConsumedAtUtc is not null)
            {
                await HandleConsumedTokenAsync(
                    latestState,
                    cancellationToken);
            }

            return null;
        }

        var newRawToken = RefreshTokenSecurity.GenerateToken();

        var newExpiration = now.AddDays(options.Value.TokenLifetimeDays);

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
            currentToken.UserId, new CreatedRefreshSession( newRawToken,newExpiration));
    }

    private async Task HandleConsumedTokenAsync(RefreshToken consumedToken,CancellationToken cancellationToken)
    {
        // IMPORTANT:
        // Get a fresh timestamp AFTER detecting consumption.
        // Do not reuse a time captured before database queries.
        var now = timeProvider.GetUtcNow().UtcDateTime;

        var consumedAt = consumedToken.ConsumedAtUtc!.Value;
        var elapsed = now - consumedAt;

        if (elapsed >= TimeSpan.Zero &&
            elapsed <= DuplicateWindow)
        {
            var successors = await dbContext.RefreshTokens
                .AsNoTracking()
                .Where(x =>
                    x.FamilyId == consumedToken.FamilyId &&
                    x.Id != consumedToken.Id &&
                    x.CreatedAtUtc >= consumedAt)
                .Select(x => new
                {
                    x.ConsumedAtUtc,
                    x.RevokedAtUtc
                })
                .Take(2)
                .ToListAsync(cancellationToken);

            if (successors.Count == 1 &&
                successors[0].ConsumedAtUtc is null &&
                successors[0].RevokedAtUtc is null)
            {
                // Reject duplicate without revoking
                // the successfully rotated session.
                return;
            }
        }

        await RevokeFamilyAsync(consumedToken.FamilyId,now,cancellationToken);
    }

    public async Task RevokeAsync(string? rawToken,CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return;

        var tokenHash = RefreshTokenSecurity.HashToken(rawToken);

        var familyId = await dbContext.RefreshTokens
            .AsNoTracking()
            .Where(x => x.TokenHash == tokenHash)
            .Select(x => (Guid?)x.FamilyId)
            .SingleOrDefaultAsync(cancellationToken);

        if (familyId is null)
            return;

        var now = timeProvider.GetUtcNow().UtcDateTime;

        await RevokeFamilyAsync(familyId.Value,now,cancellationToken);
    }

    private async Task RevokeFamilyAsync(Guid familyId,DateTime now, CancellationToken cancellationToken)
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