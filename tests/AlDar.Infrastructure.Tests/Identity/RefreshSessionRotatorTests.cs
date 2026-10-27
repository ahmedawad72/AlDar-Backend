using AlDar.Infrastructure.Authentication;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Moq;

public sealed class RefreshSessionRotatorTests
{
    [Fact]
    public async Task RotateAsync_WithValidToken_ShouldConsumeOldTokenAndCreateReplacement()
    {
        // Arrange
        await using var connection =
            new SqliteConnection("Data Source=:memory:");

        await connection.OpenAsync();

        var dbOptions =
            new DbContextOptionsBuilder<AlDarDbContext>()
                .UseSqlite(connection)
                .Options;

        await using var dbContext =
            new AlDarDbContext(dbOptions);

        await dbContext.Database.EnsureCreatedAsync();

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = "student@test.com",
            Email = "student@test.com",
            DisplayName = "Test Student"
        };

        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();

        var now = new DateTimeOffset(
            2026, 10, 27, 12, 0, 0,
            TimeSpan.Zero);

        var timeProvider = new Mock<TimeProvider>();

        timeProvider
            .Setup(x => x.GetUtcNow())
            .Returns(now);

        var options = Options.Create(
            new RefreshSessionOptions
            {
                TokenLifetimeDays = 7,
                MaxSessionLifetimeDays = 30
            });

        var issuer = new RefreshSessionIssuer(
            dbContext,
            options,
            timeProvider.Object);

        var originalSession =
            await issuer.CreateAsync(user.Id);

        var rotator = new RefreshSessionRotator(
            dbContext,
            options,
            timeProvider.Object);

        // Act
        var result = await rotator.RotateAsync(
            originalSession.RawToken);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(user.Id, result.UserId);

        Assert.NotEqual(
            originalSession.RawToken,
            result.RefreshSession.RawToken);

        var sessions = await dbContext.RefreshTokens
            .AsNoTracking()
            .OrderBy(x => x.CreatedAtUtc)
            .ToListAsync();

        Assert.Equal(2, sessions.Count);

        var oldToken = Assert.Single(
            sessions,
            x => x.TokenHash ==
                RefreshTokenSecurity.HashToken(
                    originalSession.RawToken));

        var newToken = Assert.Single(
            sessions,
            x => x.TokenHash ==
                RefreshTokenSecurity.HashToken(
                    result.RefreshSession.RawToken));

        Assert.NotNull(oldToken.ConsumedAtUtc);
        Assert.Null(newToken.ConsumedAtUtc);
        Assert.Null(newToken.RevokedAtUtc);

        Assert.Equal(oldToken.FamilyId, newToken.FamilyId);

        Assert.Equal(
            oldToken.AbsoluteExpiresAtUtc,
            newToken.AbsoluteExpiresAtUtc);

        Assert.Equal(
            newToken.ExpiresAtUtc,
            result.RefreshSession.ExpiresAtUtc);
    }

    [Fact]
    public async Task RotateAsync_WhenConsumedTokenIsReused_ShouldRevokeFamily()
    {
        // Arrange
        await using var connection =
            new SqliteConnection("Data Source=:memory:");

        await connection.OpenAsync();

        var dbOptions =
            new DbContextOptionsBuilder<AlDarDbContext>()
                .UseSqlite(connection)
                .Options;

        await using var dbContext =
            new AlDarDbContext(dbOptions);

        await dbContext.Database.EnsureCreatedAsync();

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = "student@test.com",
            Email = "student@test.com",
            DisplayName = "Test Student"
        };

        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();

        var now = new DateTimeOffset(
            2026, 10, 27, 12, 0, 0,
            TimeSpan.Zero);

        var timeProvider = new Mock<TimeProvider>();

        timeProvider
            .Setup(x => x.GetUtcNow())
            .Returns(now);

        var options = Options.Create(
            new RefreshSessionOptions
            {
                TokenLifetimeDays = 7,
                MaxSessionLifetimeDays = 30
            });

        var issuer = new RefreshSessionIssuer(
            dbContext,
            options,
            timeProvider.Object);

        var originalSession =
            await issuer.CreateAsync(user.Id);

        var rotator = new RefreshSessionRotator(
            dbContext,
            options,
            timeProvider.Object);

        // First rotation succeeds
        var firstRotation = await rotator.RotateAsync(
            originalSession.RawToken);

        Assert.NotNull(firstRotation);

        // Act: Reuse the old token
        var secondRotation = await rotator.RotateAsync(
            originalSession.RawToken);

        // Assert
        Assert.Null(secondRotation);

        var sessions = await dbContext.RefreshTokens
            .AsNoTracking()
            .ToListAsync();

        Assert.Equal(2, sessions.Count);

        Assert.All(
            sessions,
            session => Assert.NotNull(session.RevokedAtUtc));

        // Even the replacement is now rejected
        var rejectedReplacement = await rotator.RotateAsync(
            firstRotation.RefreshSession.RawToken);

        Assert.Null(rejectedReplacement);
    }
}