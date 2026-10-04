using AlDar.Api.IntegrationTests.Fakes;
using AlDar.Application.Authentication;
using AlDar.Domain.Constants;
using AlDar.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;

namespace AlDar.Api.IntegrationTests.Authentication;

public class ConfirmEmailTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public ConfirmEmailTests(
        CustomWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task ConfirmEmail_WhenTokenIsValid_ShouldConfirmUserEmail()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var registerRequest = new RegisterRequest
        {
            Email = "confirm@test.com",
            Password = "Password123!",
            DisplayName = "Confirm User",
            Role = Roles.Student
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        var sentEmail =
            Assert.Single(emailService.SentEmails);

        var confirmationLink =
            ExtractConfirmationLink(
                sentEmail.HtmlBody);

        var uri =
            new Uri(confirmationLink);

        var query =
            QueryHelpers.ParseQuery(uri.Query);

        var userId =
            query["userId"].ToString();

        var token =
            query["token"].ToString();

        var confirmRequest =
            new ConfirmEmailRequest
            {
                UserId = userId,
                Token = token
            };

        // Act
        var confirmResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/confirm-email",
                confirmRequest);

        // Assert HTTP response
        Assert.Equal(
            HttpStatusCode.NoContent,
            confirmResponse.StatusCode);

        // Assert database state
        using var scope =
            _factory.Services.CreateScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<AppUser>>();

        var user =
            await userManager.FindByEmailAsync(
                "confirm@test.com");

        Assert.NotNull(user);

        Assert.True(user.EmailConfirmed);
    }

    [Fact]
    public async Task ConfirmEmail_WhenTokenIsInvalid_ShouldReturnBadRequest()
    {
        // Arrange
        var registerRequest = new RegisterRequest
        {
            Email = "invalid-token@test.com",
            Password = "Password123!",
            DisplayName = "Invalid Token User",
            Role = Roles.Student
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        using var scope =
            _factory.Services.CreateScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<AppUser>>();

        var user =
            await userManager.FindByEmailAsync(
                "invalid-token@test.com");

        Assert.NotNull(user);

        var confirmRequest =
            new ConfirmEmailRequest
            {
                UserId = user.Id,
                Token = "this-is-not-a-valid-token"
            };

        // Act
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/confirm-email",
                confirmRequest);

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

        // Make sure the invalid token did NOT confirm the account
        var userAfterAttempt =
            await userManager.FindByEmailAsync(
                "invalid-token@test.com");

        Assert.NotNull(userAfterAttempt);

        Assert.False(
            userAfterAttempt.EmailConfirmed);
    }
    
    private static string ExtractConfirmationLink(string htmlBody)
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