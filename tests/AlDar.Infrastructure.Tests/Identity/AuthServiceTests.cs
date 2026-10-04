using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Application.Exceptions;
using AlDar.Domain.Constants;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace AlDar.Infrastructure.Tests.Identity;

public class AuthServiceTests
{
    [Fact]
    public async Task RegisterAsync_WhenEmailAlreadyExists_ShouldThrowConflictException()
    {
        // Arrange
        var existingUser = new AppUser
        {
            Email = "ahmed@test.com"
        };

        var userManager = CreateMockUserManager();

        // Means ==> If AuthService calls FindByEmailAsync("ahmed@test.com"), pretend that Identity found this user.
        userManager
            .Setup(x => x.FindByEmailAsync("ahmed@test.com"))
            .ReturnsAsync(existingUser);

        var dbContext = CreateDbContext();

        var authService = CreateAuthService(userManager, dbContext);

        var request = new RegisterRequest
        {
            Email = "ahmed@test.com",
            Password = "Password123!",
            DisplayName = "Ahmed",
            Role = Roles.Student
        };

        // Act
        var exception = await Assert.ThrowsAsync<ConflictException>(
            () => authService.RegisterAsync(request));

        // Assert
        Assert.Equal(
            "An account with this email already exists.",
            exception.Message);
    }

    [Fact]
    public async Task RegisterAsync_WhenRoleIsInvalid_ShouldThrowValidationException()
    {
        // Arrange
        var userManager = CreateMockUserManager();

        // Means ==> If AuthService calls FindByEmailAsync(), pretend that Identity did not find any user with this email.
        userManager
           .Setup(x => x.FindByEmailAsync("ahmed@test.com"))
           .ReturnsAsync((AppUser?)null);

        var dbContext = CreateDbContext();

        var authService = CreateAuthService(userManager, dbContext);


        var request = new RegisterRequest
        {
            Email = "ahmed@test.com",
            Password = "Password123!",
            DisplayName = "Ahmed",
            Role = "Admin"
        };
        
        // Act
        var exception = await Assert.ThrowsAsync<ValidationException>(
            () => authService.RegisterAsync(request));

        // Assert
        Assert.True(exception.Errors.ContainsKey("Role"));

        Assert.Contains(
            $"Role must be either '{Roles.Student}' or '{Roles.Teacher}'.",
            exception.Errors["Role"]);
    }

    [Fact]
    public async Task RegisterAsync_WhenIdentityCreationFails_ShouldThrowValidationException()
    {
        // Arrange
        var userManager = CreateMockUserManager();
       
        // Means ==> If AuthService calls FindByEmailAsync(), pretend that Identity did not find any user with this email.
        userManager
           .Setup(x => x.FindByEmailAsync("ahmed@test.com"))
           .ReturnsAsync((AppUser?)null);

        userManager
           .Setup(x => x.CreateAsync(
               It.IsAny<AppUser>(),      // I don't care which exact AppUser object is passed here. Match any AppUser.
               It.IsAny<string>()))      // password parameter
           .ReturnsAsync(
               IdentityResult.Failed(
                   new IdentityError
                   {
                       Code = "PasswordTooShort",
                       Description = "Passwords must be at least 6 characters."
                   }));

        var dbContext = CreateDbContext();

        var authService = CreateAuthService(userManager, dbContext);

        var request = new RegisterRequest
        {
            Email = "ahmed@test.com",
            Password = "123",
            DisplayName = "Ahmed",
            Role = Roles.Student
        };

        // Act
        var exception = await Assert.ThrowsAsync<ValidationException>(
            () => authService.RegisterAsync(request));

        // Assert
        Assert.True(
            exception.Errors.ContainsKey("PasswordTooShort"));

        Assert.Contains(
            "Passwords must be at least 6 characters.",
            exception.Errors["PasswordTooShort"]);
    }

    [Fact]
    public async Task RegisterAsync_WhenIdentityRoleAssignmentFails_ShouldThrowValidationException()
    {
        // Arrange
        var userManager = CreateMockUserManager();
        // Means 
        userManager
           .Setup(x => x.FindByEmailAsync("ahmed@test.com"))
           .ReturnsAsync((AppUser?)null);

        userManager
           .Setup(x => x.CreateAsync(
               It.IsAny<AppUser>(),
               It.IsAny<string>()))
           .ReturnsAsync(IdentityResult.Success);

        userManager
           .Setup(x => x.AddToRoleAsync(
               It.IsAny<AppUser>(),
               It.IsAny<string>()))
           .ReturnsAsync(
               IdentityResult.Failed(
                   new IdentityError
                   {
                       Code = "RoleAssignmentFailed",
                       Description = "Failed to assign role to user."
                   }));

        var dbContext = CreateDbContext();

        var authService = CreateAuthService(userManager, dbContext);


        var request = new RegisterRequest
        {
            Email = "ahmed@test.com",
            Password = "Password123!",
            DisplayName = "Ahmed",
            Role = Roles.Student
        };

        // Act
        var exception = await Assert.ThrowsAsync<ValidationException>(
            () => authService.RegisterAsync(request));

        // Assert
        Assert.True(
            exception.Errors.ContainsKey("RoleAssignmentFailed"));

        Assert.Contains(
            "Failed to assign role to user.",
            exception.Errors["RoleAssignmentFailed"]);

        userManager.Verify(
       x => x.CreateAsync(
           It.IsAny<AppUser>(),
           "Password123!"),
       Times.Once);

        userManager.Verify(
            x => x.AddToRoleAsync(
                It.IsAny<AppUser>(),
                Roles.Student),
            Times.Once);
    }

    [Fact]
    public async Task RegisterAsync_WhenEmailSendingFails_ShouldStillReturnSuccessfulRegistration()
    {
        // Arrange
        var userManager = CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync(
                "ahmed@test.com"))
            .ReturnsAsync((AppUser?)null);

        userManager
            .Setup(x => x.CreateAsync(
                It.IsAny<AppUser>(),
                "Password123!"))
            .ReturnsAsync(IdentityResult.Success);

        userManager
            .Setup(x => x.AddToRoleAsync(
                It.IsAny<AppUser>(),
                Roles.Student))
            .ReturnsAsync(IdentityResult.Success);

        userManager
            .Setup(x =>
                x.GenerateEmailConfirmationTokenAsync(
                    It.IsAny<AppUser>()))
            .ReturnsAsync("confirmation-token");

        var emailService =
            new Mock<IEmailService>();

        emailService
            .Setup(x => x.SendAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(
                new Exception("SMTP unavailable"));

        var dbContext = CreateDbContext();

        var authService =
            CreateAuthService(
                userManager,
                dbContext,
                emailService);

        var request = new RegisterRequest
        {
            Email = "ahmed@test.com",
            Password = "Password123!",
            DisplayName = "Ahmed",
            Role = Roles.Student
        };

        // Act
        var response =
            await authService.RegisterAsync(request);

        // Assert
        Assert.Equal(
            "ahmed@test.com",
            response.Email);

        Assert.False(
            response.ConfirmationEmailSent);
    }
    [Fact]
    public async Task RegisterAsync_WhenRequestIsValid_ShouldCreateUserAssignRoleAndSendConfirmationEmail()
    {
        // Arrange
        var userManager = CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync(
                "ahmed@test.com"))
            .ReturnsAsync((AppUser?)null);

        userManager
            .Setup(x => x.CreateAsync(
                It.IsAny<AppUser>(),
                "Password123!"))
            .ReturnsAsync(IdentityResult.Success);

        userManager
            .Setup(x => x.AddToRoleAsync(
                It.IsAny<AppUser>(),
                Roles.Student))
            .ReturnsAsync(IdentityResult.Success);

        userManager
            .Setup(x =>
                x.GenerateEmailConfirmationTokenAsync(
                    It.IsAny<AppUser>()))
            .ReturnsAsync("confirmation-token");

        var emailService =
            new Mock<IEmailService>();

        emailService
            .Setup(x => x.SendAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var dbContext = CreateDbContext();

        var authService = CreateAuthService( userManager, dbContext, emailService);

        var request = new RegisterRequest
        {
            Email = "ahmed@test.com",
            Password = "Password123!",
            DisplayName = "Ahmed",
            Role = Roles.Student
        };

        // Act
        var response =
            await authService.RegisterAsync(request);

        // Assert
        Assert.Equal( "ahmed@test.com", response.Email);

        Assert.Equal(Roles.Student, response.Role);

        Assert.True(response.ConfirmationEmailSent);

        emailService.Verify(
            x => x.SendAsync(
                "ahmed@test.com",
                "Confirm your AlDar account",
                It.Is<string>(body =>
                    body.Contains("confirmation-token")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task ResendConfirmationEmailAsync_WhenUserIsUnconfirmed_ShouldSendEmail()
    {
        // Arrange
        var user = new AppUser
        {
            Id = "user-1",
            Email = "ahmed@test.com",
            DisplayName = "Ahmed",
            EmailConfirmed = false
        };

        var userManager =
            CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync(
                "ahmed@test.com"))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(false);

        userManager
            .Setup(x =>
                x.GenerateEmailConfirmationTokenAsync(user))
            .ReturnsAsync("new-token");

        var emailService =
            new Mock<IEmailService>();

        emailService
            .Setup(x => x.SendAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var authService =
            CreateAuthService(
                userManager,
                CreateDbContext(),
                emailService);

        var request =
            new ResendConfirmationEmailRequest
            {
                Email = "ahmed@test.com"
            };

        // Act
        var result =
            await authService
                .ResendConfirmationEmailAsync(request);

        // Assert
        Assert.True(result);

        emailService.Verify(
            x => x.SendAsync(
                "ahmed@test.com",
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task ResendConfirmationEmailAsync_WhenEmailAlreadyConfirmed_ShouldNotSendEmail()
    {
        // Arrange
        var user = new AppUser
        {
            Email = "ahmed@test.com",
            EmailConfirmed = true
        };

        var userManager =
            CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync(
                "ahmed@test.com"))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(true);

        var emailService =
            new Mock<IEmailService>();

        var authService =
            CreateAuthService(
                userManager,
                CreateDbContext(),
                emailService);

        var request =
            new ResendConfirmationEmailRequest
            {
                Email = "ahmed@test.com"
            };

        // Act
        var result =
            await authService
                .ResendConfirmationEmailAsync(request);

        // Assert
        Assert.True(result);

        emailService.Verify(
            x => x.SendAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task ResendConfirmationEmailAsync_WhenUserDoesNotExist_ShouldNotSendEmail()
    {
        // Arrange
        var userManager =
            CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync(
                "unknown@test.com"))
            .ReturnsAsync((AppUser?)null);

        var emailService =
            new Mock<IEmailService>();

        var authService =
            CreateAuthService(
                userManager,
                CreateDbContext(),
                emailService);

        var request =
            new ResendConfirmationEmailRequest
            {
                Email = "unknown@test.com"
            };

        // Act
        var result =
            await authService
                .ResendConfirmationEmailAsync(request);

        // Assert
        Assert.True(result);

        emailService.Verify(
            x => x.SendAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    // ============================= private helper methods ===============================
    private static Mock<UserManager<AppUser>> CreateMockUserManager()
    {
        var store = new Mock<IUserStore<AppUser>>();

        return new Mock<UserManager<AppUser>>(
            store.Object,
            Mock.Of<IOptions<IdentityOptions>>(),
            Mock.Of<IPasswordHasher<AppUser>>(),
            Array.Empty<IUserValidator<AppUser>>(),
            Array.Empty<IPasswordValidator<AppUser>>(),
            Mock.Of<ILookupNormalizer>(),
            new IdentityErrorDescriber(),
            Mock.Of<IServiceProvider>(),
            Mock.Of<ILogger<UserManager<AppUser>>>());
    }

    private static AlDarDbContext CreateDbContext() 
    {
        var options =
             new DbContextOptionsBuilder<AlDarDbContext>()
                 .UseInMemoryDatabase(Guid.NewGuid().ToString())
                 .ConfigureWarnings(warnings =>
                     warnings.Ignore(
                         InMemoryEventId.TransactionIgnoredWarning))
                 .Options;

        return new AlDarDbContext(options);

    }

    private static AuthService CreateAuthService(
    Mock<UserManager<AppUser>> userManager,
    AlDarDbContext dbContext,
    Mock<IEmailService>? emailService = null)
    {
        emailService ??= new Mock<IEmailService>();

        var configuration =
            new ConfigurationBuilder()
                .AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["Client:BaseUrl"] =
                            "http://localhost:4200"
                    })
                .Build();

        var logger =
            Mock.Of<ILogger<AuthService>>();

        return new AuthService(
            userManager.Object,
            dbContext,
            emailService.Object,
            configuration,
            logger);
    }
}