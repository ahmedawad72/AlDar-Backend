using AlDar.Api.IntegrationTests.Fakes;
using AlDar.Application.Authentication;
using AlDar.Domain.Constants;
using AlDar.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;

namespace AlDar.Api.IntegrationTests.Authentication;

public class ResendConfirmationEmailTests
    : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public ResendConfirmationEmailTests(
        CustomWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task ResendConfirmationEmail_WhenUserIsUnconfirmed_ShouldSendEmail()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var registerRequest = new RegisterRequest
        {
            Email = "resend@test.com",
            Password = "Password123!",
            DisplayName = "Resend User",
            Role = Roles.Student
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        // Registration itself already generated one email.
        emailService.Clear();

        var resendRequest =
            new ResendConfirmationEmailRequest
            {
                Email = "resend@test.com"
            };

        // Act
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/resend-confirmation-email",
                resendRequest);

        // Assert
        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);

        var sentEmail =
            Assert.Single(emailService.SentEmails);

        Assert.Equal(
            "resend@test.com",
            sentEmail.To);

        Assert.Equal(
            "Confirm your AlDar account",
            sentEmail.Subject);
    }

    [Fact]
    public async Task ResendConfirmationEmail_WhenUserIsAlreadyConfirmed_ShouldNotSendEmail()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var registerRequest = new RegisterRequest
        {
            Email = "confirmed@test.com",
            Password = "Password123!",
            DisplayName = "Confirmed User",
            Role = Roles.Student
        };

        var registerResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                registerRequest);

        Assert.Equal(
            HttpStatusCode.Created,
            registerResponse.StatusCode);

        // Registration generated an email.
        // We don't care about that email in this test.
        emailService.Clear();

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager =
                scope.ServiceProvider
                    .GetRequiredService<UserManager<AppUser>>();

            var user =
                await userManager.FindByEmailAsync(
                    "confirmed@test.com");

            Assert.NotNull(user);

            user.EmailConfirmed = true;

            var updateResult =
                await userManager.UpdateAsync(user);

            Assert.True(updateResult.Succeeded);
        }

        var resendRequest =
            new ResendConfirmationEmailRequest
            {
                Email = "confirmed@test.com"
            };

        // Act
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/resend-confirmation-email",
                resendRequest);

        // Assert
        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);

        Assert.Empty(
            emailService.SentEmails);
    }

    [Fact]
    public async Task ResendConfirmationEmail_WhenUserDoesNotExist_ShouldReturnNoContentWithoutSendingEmail()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var request =
            new ResendConfirmationEmailRequest
            {
                Email = "unknown@test.com"
            };

        // Act
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/resend-confirmation-email",
                request);

        // Assert
        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);

        Assert.Empty(
            emailService.SentEmails);
    }
}