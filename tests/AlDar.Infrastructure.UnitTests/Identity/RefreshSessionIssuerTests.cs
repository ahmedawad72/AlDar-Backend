using AlDar.Infrastructure.Authentication;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Moq;

namespace AlDar.Infrastructure.Tests.Identity;

public class RefreshSessionIssuerTests
{
    [Fact]
    public async Task CreateAsync_ShouldPersistHashedRefreshToken()
    {
        // Arrange: Create an isolated SQLite database.
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

        // Create the user who will owner the refresh session.
        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = "student@test.com",
            Email = "student@test.com",
            DisplayName = "Test Student"
        };

        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync();

        // Use a fixed time to make expiration predictable.
        var now = new DateTimeOffset(
            2026, 10, 26, 12, 0, 0, TimeSpan.Zero);

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

        // Act: Create a refresh session.
        var result = await issuer.CreateAsync(user.Id);

        // Read using another DbContext to verify persistence.
        await using var verificationDb =
            new AlDarDbContext(dbOptions);

        var savedToken = await verificationDb.RefreshTokens
            .AsNoTracking()
            .SingleAsync();

        // Assert: Token generation and security.
        Assert.False(
            string.IsNullOrWhiteSpace(result.RawToken));

        Assert.NotEqual(
            result.RawToken,
            savedToken.TokenHash);

        Assert.Equal(
            RefreshTokenSecurity.HashToken(result.RawToken),
            savedToken.TokenHash);

        // Assert: Session ownership.
        Assert.Equal(user.Id, savedToken.UserId);

        Assert.NotEqual(Guid.Empty, savedToken.FamilyId);

        // Assert: Expiration.
        Assert.Equal(
            now.UtcDateTime,
            savedToken.CreatedAtUtc);

        Assert.Equal(
            now.UtcDateTime.AddDays(7),
            savedToken.ExpiresAtUtc);

        Assert.Equal(
            now.UtcDateTime.AddDays(30),
            savedToken.AbsoluteExpiresAtUtc);

        Assert.Equal(
            savedToken.ExpiresAtUtc,
            result.ExpiresAtUtc);

        // Assert: New session is active.
        Assert.Null(savedToken.ConsumedAtUtc);
        Assert.Null(savedToken.RevokedAtUtc);
    }
}