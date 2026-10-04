using AlDar.Api.IntegrationTests.Fakes;
using AlDar.Application.Authentication;
using AlDar.Domain.Constants;
using AlDar.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;

namespace AlDar.Api.IntegrationTests.Authentication;

public class RegisterTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public RegisterTests(
        CustomWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Register_WhenRequestIsValid_ShouldReturnCreated()
    {
        // Arrange
        var request = new RegisterRequest
        {
            Email = "integration@test.com",
            Password = "Password123!",
            DisplayName = "Integration User",
            Role = Roles.Student
        };

        // Act
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                request);

        // Assert
        Assert.Equal(
            HttpStatusCode.Created,
            response.StatusCode);
    }
   
    [Fact]
    public async Task Register_WhenRequestIsValid_ShouldPersistUserWithCorrectRoleAndSendConfirmationEmail()
    {
        // Arrange
        var emailService =
            _factory.Services
                .GetRequiredService<TestEmailService>();

        emailService.Clear();

        var request = new RegisterRequest
        {
            Email = "persisted@test.com",
            Password = "Password123!",
            DisplayName = "Persisted User",
            Role = Roles.Student
        };

        // Act
        var response =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                request);

        // Assert HTTP response
        Assert.Equal(
            HttpStatusCode.Created,
            response.StatusCode);

        // Assert database state
        using var scope =
            _factory.Services.CreateScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<AppUser>>();

        var user =
            await userManager.FindByEmailAsync(
                "persisted@test.com");

        Assert.NotNull(user);

        Assert.Equal(
            "Persisted User",
            user.DisplayName);

        Assert.Equal(
            "persisted@test.com",
            user.Email);

        Assert.False(user.EmailConfirmed);

        var roles =
            await userManager.GetRolesAsync(user);

        Assert.Contains(
            Roles.Student,
            roles);

        // Assert email
        var sentEmail =
            Assert.Single(emailService.SentEmails);

        Assert.Equal(
            "persisted@test.com",
            sentEmail.To);

        Assert.Equal(
            "Confirm your AlDar account",
            sentEmail.Subject);

        Assert.Contains(
            "http://localhost:4200/confirm-email",
            sentEmail.HtmlBody);
    }
    [Fact]
    public async Task Register_WhenEmailAlreadyExists_ShouldReturnConflict()
    {
        // Arrange
        var request = new RegisterRequest
        {
            Email = "duplicate@test.com",
            Password = "Password123!",
            DisplayName = "Duplicate User",
            Role = Roles.Student
        };

        var firstResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                request);

        Assert.Equal(
            HttpStatusCode.Created,
            firstResponse.StatusCode);

        // Act
        var secondResponse =
            await _client.PostAsJsonAsync(
                "/api/auth/register",
                request);

        // Assert
        Assert.Equal(
            HttpStatusCode.Conflict,
            secondResponse.StatusCode);

        var problemDetails =
            await secondResponse.Content
                .ReadFromJsonAsync<ProblemDetails>();

        Assert.NotNull(problemDetails);

        Assert.Equal(
            "Conflict",
            problemDetails.Title);

        Assert.Equal(
            "An account with this email already exists.",
            problemDetails.Detail);
    }
}