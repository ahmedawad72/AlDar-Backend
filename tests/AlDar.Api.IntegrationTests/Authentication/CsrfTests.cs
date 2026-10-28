
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AlDar.Api.IntegrationTests.Authentication;

public sealed class CsrfTests
    : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;

    public CsrfTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task GetCsrf_ShouldReturnTokenAndSecureCookie()
    {
        // Arrange
        using var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                HandleCookies = false
            });

        // Act
        using var response = await client.GetAsync(
            "/api/auth/csrf");

        // Assert: HTTP response
        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        // Assert: Request token is returned in JSON.
        var json = await response.Content.ReadAsStringAsync();

        using var document = JsonDocument.Parse(json);

        var csrfToken = document.RootElement
            .GetProperty("token")
            .GetString();

        Assert.False(string.IsNullOrWhiteSpace(csrfToken));

        // Assert: Antiforgery cookie is issued.
        Assert.True(
            response.Headers.TryGetValues(
                "Set-Cookie",
                out var cookies));

        var csrfCookie = Assert.Single(
            cookies!,
            cookie => cookie.StartsWith(
                "aldar.csrf=",
                StringComparison.OrdinalIgnoreCase));

        Assert.Contains(
            "httponly",
            csrfCookie,
            StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            "secure",
            csrfCookie,
            StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            "samesite=strict",
            csrfCookie,
            StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            "path=/api/auth",
            csrfCookie,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Refresh_WithoutCsrfToken_ShouldReturnBadRequest()
    {
        // Arrange
        using var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                HandleCookies = false
            });

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/api/auth/refresh");

        // Send a refresh cookie, but no CSRF credentials.
        request.Headers.TryAddWithoutValidation(
            "Cookie",
            "aldar.refresh=some-refresh-token");

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);
    }
}
