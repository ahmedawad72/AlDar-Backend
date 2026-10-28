using AlDar.Api.IntegrationTests.Fakes;
using AlDar.Application.Authentication;
using AlDar.Application.Exceptions;
using AlDar.Domain.Constants;
using AlDar.Infrastructure.Authentication;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;

namespace AlDar.Api.IntegrationTests.Authentication;

public class LoginTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public LoginTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient(
            new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                HandleCookies = false,
                AllowAutoRedirect = false
            });
    }

    [Fact]
    public async Task Login_WhenUserDoesNotExist_ShouldReturnUnauthorized()
    {
        // Arrange
        var request =
            new LoginRequest
            {
                Email = "missing@test.com",
                Password = "Password123!"
            };

        // Act
        var response =
            await CsrfTestRequest.PostAsync(
                _client,
                "/api/auth/login",
                request);

        // Assert
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);

        var problemDetails =
            await response.Content
                .ReadFromJsonAsync<ProblemDetails>();

        Assert.NotNull(problemDetails);

        Assert.Equal(
            "Unauthorized",
            problemDetails.Title);

        Assert.Equal(
            "Invalid email or password.",
            problemDetails.Detail);
    }

    [Fact]
    public async Task Login_WhenEmailIsNotConfirmed_ShouldReturnForbiddenWithEmailNotConfirmedCode()
    {
        // Arrange
        var registerRequest =
            new RegisterRequest
            {
                Email = "unconfirmed-login@test.com",
                Password = "Password123!",
                DisplayName = "Unconfirmed User",
                Role = Roles.Student
            };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var loginRequest =
            new LoginRequest
            {
                Email = "unconfirmed-login@test.com",
                Password = "Password123!"
            };

        // Act
        var response =
            await CsrfTestRequest.PostAsync(
                _client,
                "/api/auth/login",
                loginRequest);

        // Assert
        Assert.Equal(
            HttpStatusCode.Forbidden,
            response.StatusCode);

        var problemDetails =
            await response.Content
                .ReadFromJsonAsync<ProblemDetails>();

        Assert.NotNull(problemDetails);

        Assert.Equal(
            "Forbidden",
            problemDetails.Title);

        Assert.Equal(
            "Email confirmation is required before login.",
            problemDetails.Detail);

        Assert.True(
            problemDetails.Extensions.TryGetValue( "code",out var codeValue));

        var code =
            codeValue switch
            {
                JsonElement jsonElement =>
                    jsonElement.GetString(),

                string value =>
                    value,

                _ =>
                    codeValue?.ToString()
            };

        Assert.Equal(EmailNotConfirmedException.ErrorCode,code);
    }

    [Fact]
    public async Task Login_WhenCredentialsAreValidAndEmailIsConfirmed_ShouldReturnJwt()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var registerRequest =
            new RegisterRequest
            {
                Email = "valid-login@test.com",
                Password = "Password123!",
                DisplayName = "Valid Login User",
                Role = Roles.Student
            };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        // Registration should have produced the confirmation email.
        var confirmationEmail =
            Assert.Single(emailService.SentEmails);

        var confirmationLink =
            ExtractConfirmationLink(
                confirmationEmail.HtmlBody);

        var confirmationUri =
            new Uri(confirmationLink);

        var query =
            QueryHelpers.ParseQuery(
                confirmationUri.Query);

        var confirmRequest =
            new ConfirmEmailRequest
            {
                UserId =
                    query["userId"].ToString(),

                Token =
                    query["token"].ToString()
            };

        var confirmResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/confirm-email",
                confirmRequest);

        Assert.Equal(
            HttpStatusCode.NoContent,
            confirmResponse.StatusCode);

        var loginRequest =
            new LoginRequest
            {
                Email = "valid-login@test.com",
                Password = "Password123!"
            };

        // Act
        var response =
            await CsrfTestRequest.PostAsync(
                _client,
                "/api/auth/login",
                loginRequest);

        // Assert
        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        var loginResponse =
            await response.Content
                .ReadFromJsonAsync<LoginResponse>();

        Assert.NotNull(loginResponse);

        Assert.False(
            string.IsNullOrWhiteSpace(
                loginResponse.AccessToken));

        Assert.Equal(
            "valid-login@test.com",
            loginResponse.Email);

        Assert.Equal(
            "Valid Login User",
            loginResponse.DisplayName);

        Assert.Contains(
            Roles.Student,
            loginResponse.Roles);

        Assert.True(
            loginResponse.ExpiresAtUtc >
            DateTimeOffset.UtcNow);

        Assert.False(
            string.IsNullOrWhiteSpace(
                loginResponse.UserId));
    }

    [Fact]
    public async Task Login_AfterTooManyFailedAttempts_ShouldReturnAccountLocked()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var email =
            "locked-login@test.com";

        var password =
            "Password123!";

        var registerRequest =
            new RegisterRequest
            {
                Email = email,
                Password = password,
                DisplayName = "Locked User",
                Role = Roles.Student
            };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        // Confirm the account first.
        var confirmationEmail =
            Assert.Single(emailService.SentEmails);

        var confirmationLink =
            ExtractConfirmationLink(
                confirmationEmail.HtmlBody);

        var confirmationUri =
            new Uri(confirmationLink);

        var query =
            QueryHelpers.ParseQuery(
                confirmationUri.Query);

        var confirmRequest =
            new ConfirmEmailRequest
            {
                UserId =
                    query["userId"].ToString(),

                Token =
                    query["token"].ToString()
            };

        var confirmResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/confirm-email",
                confirmRequest);

        Assert.Equal(
            HttpStatusCode.NoContent,
            confirmResponse.StatusCode);

        var wrongLoginRequest =
            new LoginRequest
            {
                Email = email,
                Password = "WrongPassword123!"
            };

        // Act - fail 5 times.
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var failedResponse =
                await CsrfTestRequest.PostAsync(
                    _client,
                    "/api/auth/login",
                    wrongLoginRequest);

            Assert.Equal(
                HttpStatusCode.Unauthorized,
                failedResponse.StatusCode);
        }

        // Now try the CORRECT password.
        var correctLoginRequest =
            new LoginRequest
            {
                Email = email,
                Password = password
            };

        var lockedResponse =
            await CsrfTestRequest.PostAsync(
                _client,
                "/api/auth/login",
                correctLoginRequest);

        // Assert
        Assert.Equal(
            (HttpStatusCode)423,
            lockedResponse.StatusCode);

        var problemDetails =
            await lockedResponse.Content
                .ReadFromJsonAsync<ProblemDetails>();

        Assert.NotNull(problemDetails);

        Assert.Equal(
            "Account locked",
            problemDetails.Title);

        Assert.Equal(
            "Your account is temporarily locked due to multiple failed login attempts.",
            problemDetails.Detail);

        Assert.True(
            problemDetails.Extensions.TryGetValue(
                "code",
                out var codeValue));

        var code =
            codeValue switch
            {
                JsonElement jsonElement =>
                    jsonElement.GetString(),

                string value =>
                    value,

                _ =>
                    codeValue?.ToString()
            };

        Assert.Equal(
            AccountLockedException.ErrorCode,
            code);

        Assert.True(
            problemDetails.Extensions.ContainsKey(
                "lockedUntilUtc"));
    }

    [Fact]
    public async Task Me_WhenTokenIsMissing_ShouldReturnUnauthorized()
    {
        // Act
        var response =
            await _client.GetAsync(
                "/api/auth/me");

        // Assert
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Me_WhenJwtIsValid_ShouldReturnAuthenticatedUser()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var email =
            "authenticated@test.com";

        var password =
            "Password123!";

        var registerRequest =
            new RegisterRequest
            {
                Email = email,
                Password = password,
                DisplayName = "Authenticated User",
                Role = Roles.Student
            };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var confirmationEmail =
            Assert.Single(
                emailService.SentEmails);

        var confirmationLink =
            ExtractConfirmationLink(
                confirmationEmail.HtmlBody);

        var confirmationUri =
            new Uri(confirmationLink);

        var query =
            QueryHelpers.ParseQuery(
                confirmationUri.Query);

        var confirmRequest =
            new ConfirmEmailRequest
            {
                UserId =
                    query["userId"].ToString(),

                Token =
                    query["token"].ToString()
            };

        var confirmResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/confirm-email",
                confirmRequest);

        Assert.Equal(
            HttpStatusCode.NoContent,
            confirmResponse.StatusCode);

        var loginResponse =
            await CsrfTestRequest.PostAsync(
                _client,
                "/api/auth/login",
                new LoginRequest
                {
                    Email = email,
                    Password = password
                });

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var login =
            await loginResponse.Content
                .ReadFromJsonAsync<LoginResponse>();

        Assert.NotNull(login);

        // Send JWT back to the API.
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                login.AccessToken);

        // Act
        var response =
            await _client.GetAsync(
                "/api/auth/me");

        // Assert
        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        var currentUser =
            await response.Content
                .ReadFromJsonAsync<CurrentUserResponse>();

        Assert.NotNull(currentUser);

        Assert.Equal(
            login.UserId,
            currentUser.UserId);

        Assert.Equal(
            email,
            currentUser.Email);

        Assert.Contains(
            Roles.Student,
            currentUser.Roles);

        _client.DefaultRequestHeaders.Authorization = null;
    }

    [Fact]
    public async Task Login_WhenEmailAndPasswordAreEmpty_ShouldReturnBadRequest()
    {
        // Arrange
        var request =
            new LoginRequest
            {
                Email = string.Empty,
                Password = string.Empty
            };

        // Act
        var response =
            await CsrfTestRequest.PostAsync(
                _client,
                "/api/auth/login",
                request);

        // Assert
        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        var problemDetails =
            await response.Content
                .ReadFromJsonAsync<ProblemDetails>();

        Assert.NotNull(problemDetails);

        Assert.Equal(
            "Validation failed",
            problemDetails.Title);

        Assert.True(
            problemDetails.Extensions.ContainsKey(
                "errors"));
    }

    [Fact]
    public async Task Login_WhenSuccessful_ShouldSetSecureRefreshCookie()
    {
        // Arrange
        var emailService =
            _factory.Services.GetRequiredService<TestEmailService>();

        emailService.Clear();

        var email = "refresh-cookie@test.com";
        var password = "Password123!";

        var registerRequest = new RegisterRequest
        {
            Email = email,
            Password = password,
            DisplayName = "Refresh Cookie User",
            Role = Roles.Student
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        // Confirm the email
        var confirmationEmail =
            Assert.Single(emailService.SentEmails);

        var confirmationLink =
            ExtractConfirmationLink(
                confirmationEmail.HtmlBody);

        var confirmationUri = new Uri(confirmationLink);

        var query =
            QueryHelpers.ParseQuery(
                confirmationUri.Query);

        var confirmRequest = new ConfirmEmailRequest
        {
            UserId = query["userId"].ToString(),
            Token = query["token"].ToString()
        };

        var confirmResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/confirm-email",
                confirmRequest);

        Assert.Equal(
            HttpStatusCode.NoContent,
            confirmResponse.StatusCode);

        // Act: Login
        var loginResponse =
            await CsrfTestRequest.PostAsync(
                _client,
                "/api/auth/login",
                new LoginRequest
                {
                    Email = email,
                    Password = password
                });

        // Assert: Login succeeded
        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var login =
            await loginResponse.Content
                .ReadFromJsonAsync<LoginResponse>();

        Assert.NotNull(login);
        Assert.False(string.IsNullOrWhiteSpace(login.AccessToken));

        // Assert: Refresh cookie exists
        Assert.True(
            loginResponse.Headers.TryGetValues(
                "Set-Cookie",
                out var cookies));

        var refreshCookie = Assert.Single(
            cookies!,
            cookie => cookie.StartsWith(
                "aldar.refresh=",
                StringComparison.OrdinalIgnoreCase));

        Assert.Contains(
            "httponly",
            refreshCookie,
            StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            "secure",
            refreshCookie,
            StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            "samesite=strict",
            refreshCookie,
            StringComparison.OrdinalIgnoreCase);

        Assert.Contains(
            "path=/api/auth",
            refreshCookie,
            StringComparison.OrdinalIgnoreCase);

        // Extract raw token from Set-Cookie for testing only
        var rawToken = refreshCookie
            .Split(';')[0]
            .Split('=', 2)[1];

        Assert.False(string.IsNullOrWhiteSpace(rawToken));

        // Assert: Database stores only token hash
        using var scope = _factory.Services.CreateScope();

        var dbContext =
            scope.ServiceProvider
                .GetRequiredService<AlDarDbContext>();

        var savedSession =
            await dbContext.RefreshTokens
                .AsNoTracking()
                .SingleAsync(x => x.UserId == login.UserId);

        Assert.Equal(
            RefreshTokenSecurity.HashToken(rawToken),
            savedSession.TokenHash);

        Assert.NotEqual(
            rawToken,
            savedSession.TokenHash);

        // Assert: Refresh token is NOT in JSON
        var responseJson =
            await loginResponse.Content.ReadAsStringAsync();

        using var document =
            JsonDocument.Parse(responseJson);

        Assert.False(
            document.RootElement.TryGetProperty(
                "refreshToken",
                out _));

        Assert.False(
            document.RootElement.TryGetProperty(
                "refreshSession",
                out _));

        Assert.False(
            document.RootElement.TryGetProperty(
                "rawToken",
                out _));

        Assert.DoesNotContain(
            rawToken,
            responseJson);
    }


    [Fact]
    public async Task Login_WithoutCsrfToken_ShouldReturnBadRequest()
    {
        // Arrange: a syntactically valid login request without CSRF credentials.
        var request = new LoginRequest
        {
            Email = "missing-csrf@test.com",
            Password = "Password123!"
        };

        // Act: deliberately bypass CsrfTestRequest.
        using var response = await _client.PostAsJsonAsync(
            "/api/auth/login", request);

        // Assert: CSRF validation rejects the request before login executes.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // _____________________________Private Helper Methods_____________________________
    private static string ExtractConfirmationLink( string htmlBody)
    {
        var decodedHtml =
            WebUtility.HtmlDecode(htmlBody);

        var match =
            Regex.Match(
                decodedHtml,
                "href=\"([^\"]+)\"");

        Assert.True(
            match.Success,
            "Confirmation link was not found in the email.");

        return match.Groups[1].Value;
    }
}