
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AlDar.Infrastructure.Authentication;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AlDar.Api.IntegrationTests.Authentication;

public sealed class RefreshTests : IClassFixture<CustomWebApplicationFactory>, IDisposable
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public RefreshTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;

        // We control cookies explicitly in each request.
        _client = factory.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                HandleCookies = false,
                AllowAutoRedirect = false
            });
    }

    [Fact]
    public async Task Refresh_WithValidCookie_ShouldRotateTokenAndReturnNewJwt()
    {
        // Arrange: create a confirmed student and log in.
        var user = await CreateConfirmedStudentAsync();

        using var loginResponse =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var originalToken = GetRefreshToken(loginResponse);

        // Act
        using var refreshResponse =
            await PostRefreshAsync(originalToken);

        // Assert: HTTP response
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);

        var replacementToken = GetRefreshToken(refreshResponse);

        Assert.NotEqual(originalToken, replacementToken);

        var setCookie = GetRefreshCookieHeader(refreshResponse);

        Assert.True(setCookie.Contains(
            "httponly", StringComparison.OrdinalIgnoreCase));

        Assert.True(setCookie.Contains(
            "secure", StringComparison.OrdinalIgnoreCase));

        Assert.True(setCookie.Contains(
            "samesite=strict", StringComparison.OrdinalIgnoreCase));

        Assert.True(setCookie.Contains(
            "path=/api/auth", StringComparison.OrdinalIgnoreCase));

        // Assert: JSON contains the JWT but not the refresh token.
        var json = await refreshResponse.Content.ReadAsStringAsync();

        using var document = JsonDocument.Parse(json);

        var root = document.RootElement;

        Assert.False(string.IsNullOrWhiteSpace(
            root.GetProperty("accessToken").GetString()));

        Assert.Equal(
            user.UserId,
            root.GetProperty("userId").GetString());

        Assert.Equal(
            user.Email,
            root.GetProperty("email").GetString());

        Assert.False(root.TryGetProperty("refreshToken", out _));
        Assert.False(root.TryGetProperty("refreshSession", out _));
        Assert.False(root.TryGetProperty("rawToken", out _));

        Assert.DoesNotContain(replacementToken, json);

        // Assert: database contains both records and only hashes.
        using var scope = _factory.Services.CreateScope();

        var dbContext =
            scope.ServiceProvider.GetRequiredService<AlDarDbContext>();

        var sessions = await dbContext.RefreshTokens
            .AsNoTracking()
            .Where(x => x.UserId == user.UserId)
            .ToListAsync();

        Assert.Equal(2, sessions.Count);

        var oldSession = Assert.Single(
            sessions,
            x => x.TokenHash ==
                RefreshTokenSecurity.HashToken(originalToken));

        var newSession = Assert.Single(
            sessions,
            x => x.TokenHash ==
                RefreshTokenSecurity.HashToken(replacementToken));

        Assert.NotNull(oldSession.ConsumedAtUtc);
        Assert.Null(newSession.ConsumedAtUtc);
        Assert.Null(newSession.RevokedAtUtc);

        Assert.Equal(oldSession.FamilyId, newSession.FamilyId);

        Assert.Equal(
            oldSession.AbsoluteExpiresAtUtc,
            newSession.AbsoluteExpiresAtUtc);

        Assert.NotEqual(replacementToken, newSession.TokenHash);
    }

    [Fact]
    public async Task Refresh_WithoutCookie_ShouldReturnUnauthorized()
    {
        // Act
        using var response =
            await _client.PostAsync("/api/auth/refresh", null);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Refresh_WithInvalidCookie_ShouldReturnUnauthorized()
    {
        // Act
        using var response =
            await PostRefreshAsync("invalid-refresh-token");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Refresh_WithExpiredToken_ShouldReturnUnauthorized()
    {
        // Arrange
        var user = await CreateConfirmedStudentAsync();

        using var loginResponse =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var rawToken = GetRefreshToken(loginResponse);

        // Expire the session directly in the test database.
        using (var scope = _factory.Services.CreateScope())
        {
            var dbContext =
                scope.ServiceProvider.GetRequiredService<AlDarDbContext>();

            var session = await dbContext.RefreshTokens.SingleAsync(
                x => x.TokenHash ==
                    RefreshTokenSecurity.HashToken(rawToken));

            session.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);

            await dbContext.SaveChangesAsync();
        }

        // Act
        using var response = await PostRefreshAsync(rawToken);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        using var verificationScope = _factory.Services.CreateScope();

        var verificationDb =
            verificationScope.ServiceProvider
                .GetRequiredService<AlDarDbContext>();

        var sessionCount = await verificationDb.RefreshTokens
            .CountAsync(x => x.UserId == user.UserId);

        // No replacement should have been created.
        Assert.Equal(1, sessionCount);
    }

    [Fact]
    public async Task Refresh_WhenOldTokenIsReusedAfterWindow_ShouldRevokeFamily()
    {
        // Arrange
        var user = await CreateConfirmedStudentAsync();

        using var loginResponse =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var originalToken = GetRefreshToken(loginResponse);

        using var firstRefresh =
            await PostRefreshAsync(originalToken);

        Assert.Equal(HttpStatusCode.OK, firstRefresh.StatusCode);

        var replacementToken = GetRefreshToken(firstRefresh);

        // Simulate the first token having been consumed
        // more than five seconds ago.
        using (var scope = _factory.Services.CreateScope())
        {
            var dbContext =
                scope.ServiceProvider.GetRequiredService<AlDarDbContext>();

            var oldSession = await dbContext.RefreshTokens.SingleAsync(
                x => x.TokenHash ==
                    RefreshTokenSecurity.HashToken(originalToken));

            oldSession.ConsumedAtUtc =
                DateTime.UtcNow.AddMinutes(-1);

            await dbContext.SaveChangesAsync();
        }

        // Act: reuse the old token outside the window.
        using var replayResponse =
            await PostRefreshAsync(originalToken);

        // Assert
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            replayResponse.StatusCode);

        // The replacement must also be rejected.
        using var nextResponse =
            await PostRefreshAsync(replacementToken);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            nextResponse.StatusCode);

        using var verificationScope = _factory.Services.CreateScope();

        var verificationDb =
            verificationScope.ServiceProvider
                .GetRequiredService<AlDarDbContext>();

        var sessions = await verificationDb.RefreshTokens
            .AsNoTracking()
            .Where(x => x.UserId == user.UserId)
            .ToListAsync();

        Assert.Equal(2, sessions.Count);

        Assert.All(
            sessions,
            session => Assert.NotNull(session.RevokedAtUtc));
    }

    [Fact]
    public async Task Logout_WithValidCookie_ShouldRevokeSessionAndDeleteCookie()
    {
        // Arrange
        var user = await CreateConfirmedStudentAsync();

        using var loginResponse =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var rawToken = GetRefreshToken(loginResponse);

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/api/auth/logout");

        request.Headers.TryAddWithoutValidation(
            "Cookie",
            $"aldar.refresh={rawToken}");

        // Act
        using var response = await _client.SendAsync(request);

        // Assert: Logout succeeds
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        // Assert: Cookie is deleted
        var cookieHeader = GetRefreshCookieHeader(response);

        Assert.Contains(
            "path=/api/auth",
            cookieHeader,
            StringComparison.OrdinalIgnoreCase);

        var cookieValue = cookieHeader.Split(';', 2)[0];

        Assert.Equal("aldar.refresh=", cookieValue);

        Assert.True(
            cookieHeader.Contains(
                "expires=",
                StringComparison.OrdinalIgnoreCase) ||
            cookieHeader.Contains(
                "max-age=0",
                StringComparison.OrdinalIgnoreCase));

        // Assert: Database session was revoked
        using var scope = _factory.Services.CreateScope();

        var dbContext =
            scope.ServiceProvider.GetRequiredService<AlDarDbContext>();

        var session = await dbContext.RefreshTokens
            .AsNoTracking()
            .SingleAsync(x =>
                x.TokenHash ==
                RefreshTokenSecurity.HashToken(rawToken));

        Assert.NotNull(session.RevokedAtUtc);

        // Assert: Revoked token cannot refresh
        using var refreshResponse =
            await PostRefreshAsync(rawToken);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            refreshResponse.StatusCode);
    }

    [Fact]
    public async Task Logout_WithoutCookie_ShouldReturnNoContent()
    {
        // Act
        using var response = await _client.PostAsync(
            "/api/auth/logout",
            null);

        // Assert
        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);

        // The server should still instruct the browser
        // to remove the refresh cookie.
        var cookieHeader = GetRefreshCookieHeader(response);

        Assert.StartsWith(
            "aldar.refresh=",
            cookieHeader);

        Assert.Contains(
            "path=/api/auth",
            cookieHeader,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Logout_OneSession_ShouldNotRevokeOtherSessions()
    {
        // Arrange
        var user = await CreateConfirmedStudentAsync();

        // First login: Laptop
        using var laptopLogin =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(HttpStatusCode.OK, laptopLogin.StatusCode);

        var laptopToken = GetRefreshToken(laptopLogin);

        // Second login: Phone
        using var phoneLogin =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(HttpStatusCode.OK, phoneLogin.StatusCode);

        var phoneToken = GetRefreshToken(phoneLogin);

        Assert.NotEqual(laptopToken, phoneToken);

        // Act: Logout from laptop
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/api/auth/logout");

        request.Headers.TryAddWithoutValidation(
            "Cookie",
            $"aldar.refresh={laptopToken}");

        using var logoutResponse =
            await _client.SendAsync(request);

        // Assert: Logout succeeds
        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        // Laptop session is no longer valid
        using var laptopRefresh =
            await PostRefreshAsync(laptopToken);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            laptopRefresh.StatusCode);

        // Phone session still works
        using var phoneRefresh =
            await PostRefreshAsync(phoneToken);

        Assert.Equal(
            HttpStatusCode.OK,
            phoneRefresh.StatusCode);

        // Verify database state
        using var scope = _factory.Services.CreateScope();

        var dbContext =
            scope.ServiceProvider.GetRequiredService<AlDarDbContext>();

        var laptopSession =
            await dbContext.RefreshTokens
                .AsNoTracking()
                .SingleAsync(x =>
                    x.TokenHash ==
                    RefreshTokenSecurity.HashToken(laptopToken));

        var phoneSession =
            await dbContext.RefreshTokens
                .AsNoTracking()
                .SingleAsync(x =>
                    x.TokenHash ==
                    RefreshTokenSecurity.HashToken(phoneToken));

        Assert.NotNull(laptopSession.RevokedAtUtc);
        Assert.NotEqual(laptopSession.FamilyId, phoneSession.FamilyId);
        Assert.NotNull(phoneSession.ConsumedAtUtc);
        Assert.Null(phoneSession.RevokedAtUtc);
    }

    [Fact]    //Two browser tabs send the same refresh token almost simultaneously.
    public async Task Refresh_WhenTokenIsImmediatelyRetried_ShouldPreserveNewSession()
    {
        // Arrange
        var user = await CreateConfirmedStudentAsync();

        using var loginResponse =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var originalToken = GetRefreshToken(loginResponse);

        // First refresh succeeds.
        using var firstRefresh =
            await PostRefreshAsync(originalToken);

        Assert.Equal(
            HttpStatusCode.OK,
            firstRefresh.StatusCode);

        var replacementToken = GetRefreshToken(firstRefresh);

        // Act: A second request carries the previous token.
        using var duplicateRefresh =
            await PostRefreshAsync(originalToken);

        // Duplicate request must not receive credentials.
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            duplicateRefresh.StatusCode);

        // But the successfully rotated session
        // should remain valid.
        using var validRefresh =
            await PostRefreshAsync(replacementToken);

        Assert.Equal(
            HttpStatusCode.OK,
            validRefresh.StatusCode);
    }

    [Fact]
    public async Task Refresh_WhenTwoRequestsArriveTogether_ShouldPreserveSession()
    {
        // Arrange
        var user = await CreateConfirmedStudentAsync();

        using var loginResponse =
            await LoginAsync(user.Email, user.Password);

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var originalToken = GetRefreshToken(loginResponse);

        // Act: Two requests using the same refresh token.
        var firstTask = PostRefreshAsync(originalToken);
        var secondTask = PostRefreshAsync(originalToken);

        var responses = await Task.WhenAll(
            firstTask,
            secondTask);

        using var firstResponse = responses[0];
        using var secondResponse = responses[1];

        // Diagnose the actual responses.
        var firstStatus = firstResponse.StatusCode;
        var secondStatus = secondResponse.StatusCode;

        var successCount = responses.Count(
            x => x.StatusCode == HttpStatusCode.OK);

        var unauthorizedCount = responses.Count(
            x => x.StatusCode == HttpStatusCode.Unauthorized);

        var statusReport =
            $"First: {(int)firstStatus} {firstStatus}, " +
            $"Second: {(int)secondStatus} {secondStatus}. " +
            $"Success count: {successCount}, " +
            $"Unauthorized count: {unauthorizedCount}.";

        // Assert: Exactly one request must succeed.
        Assert.True(
            successCount == 1 && unauthorizedCount == 1,
            $"Unexpected concurrent refresh results. {statusReport}");

        var successfulResponse = responses.Single(
            x => x.StatusCode == HttpStatusCode.OK);

        var replacementToken =
            GetRefreshToken(successfulResponse);

        Assert.NotEqual(originalToken, replacementToken);

        // Assert: Database contains exactly two tokens.
        using (var scope = _factory.Services.CreateScope())
        {
            var dbContext =
                scope.ServiceProvider.GetRequiredService<AlDarDbContext>();

            var sessions = await dbContext.RefreshTokens
                .AsNoTracking()
                .Where(x => x.UserId == user.UserId)
                .ToListAsync();

            Assert.Equal(2, sessions.Count);

            Assert.Single(
                sessions,
                x => x.ConsumedAtUtc is not null);

            Assert.Single(
                sessions,
                x => x.ConsumedAtUtc is null &&
                     x.RevokedAtUtc is null);
        }

        // Assert: Replacement token remains usable.
        using var nextRefresh =
            await PostRefreshAsync(replacementToken);

        Assert.Equal(
            HttpStatusCode.OK,
            nextRefresh.StatusCode);
    }
    // ------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------

    private async Task<(string UserId, string Email, string Password)>CreateConfirmedStudentAsync()
    {
        using var scope = _factory.Services.CreateScope();

        var userManager =
            scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();

        var roleManager =
            scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        const string password = "Password123!";

        var email = $"refresh-{Guid.NewGuid():N}@test.com";

        var user = new AppUser
        {
            UserName = email,
            Email = email,
            DisplayName = "Refresh Test Student",
            EmailConfirmed = true
        };

        var createResult = await userManager.CreateAsync(user, password);

        Assert.True(
            createResult.Succeeded,
            string.Join(", ", createResult.Errors.Select(x => x.Description)));

        // Create the test role only if it has not been seeded.
        if (!await roleManager.RoleExistsAsync("Student"))
        {
            var roleResult =
                await roleManager.CreateAsync(new IdentityRole("Student"));

            Assert.True(roleResult.Succeeded);
        }

        var addRoleResult =
            await userManager.AddToRoleAsync(user, "Student");

        Assert.True(addRoleResult.Succeeded);

        return (user.Id, email, password);
    }

    private Task<HttpResponseMessage> LoginAsync(string email,string password)
    {
        return _client.PostAsJsonAsync(
            "/api/auth/login",
            new
            {
                Email = email,
                Password = password
            });
    }

    private async Task<HttpResponseMessage> PostRefreshAsync(string rawToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/api/auth/refresh");

        request.Headers.TryAddWithoutValidation(
            "Cookie",
            $"aldar.refresh={rawToken}");

        return await _client.SendAsync(request);
    }

    private static string GetRefreshCookieHeader(HttpResponseMessage response)
    {
        Assert.True(
            response.Headers.TryGetValues(
                "Set-Cookie",
                out var cookieHeaders));

        return Assert.Single(
            cookieHeaders!,
            cookie => cookie.StartsWith(
                "aldar.refresh=",
                StringComparison.OrdinalIgnoreCase));
    }

    private static string GetRefreshToken(HttpResponseMessage response)
    {
        var header = GetRefreshCookieHeader(response);

        var cookiePair = header.Split(';', 2)[0];

        var rawToken =
            cookiePair["aldar.refresh=".Length..];

        Assert.False(string.IsNullOrWhiteSpace(rawToken));

        return rawToken;
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}
