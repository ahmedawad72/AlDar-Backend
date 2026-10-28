using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Application.Exceptions;
using AlDar.Domain.Constants;
using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
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
            "An account with this email already exists.", exception.Message);
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

    [Fact]
    public async Task Login_WhenUserDoesNotExist_ShouldThrowInvalidCredentialsException()
    {
        // Arrange
        var userManager = CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync( "missing@test.com"))
            .ReturnsAsync((AppUser?)null);

        await using var dbContext = CreateDbContext();

        var jwtTokenGenerator =
            new Mock<IJwtTokenGenerator>();

        var authService =
            CreateAuthService(
                userManager,
                dbContext,
                jwtTokenGenerator:
                    jwtTokenGenerator);

        var request =
            new LoginRequest
            {
                Email = "missing@test.com",
                Password = "Password123!"
            };

        // Act
        var action =
            async () =>
                await authService.LoginAsync(request);

        // Assert
        var exception =
            await Assert.ThrowsAsync<
                InvalidCredentialsException>(
                action);

        Assert.Equal( "Invalid email or password.", exception.Message);

        jwtTokenGenerator.Verify(
            x => x.Generate(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Never);
    }

    [Fact]
    public async Task Login_WhenPasswordIsWrong_ShouldRecordFailedAttemptAndThrowInvalidCredentialsException()
    {
        // Arrange
        var user =
            new AppUser
            {
                Id = "user-123",
                Email = "student@test.com",
                DisplayName = "Student User"
            };

        var userManager = CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync( "student@test.com"))
            .ReturnsAsync(user);

        userManager
            .Setup(x =>x.CheckPasswordAsync( user, "WrongPassword123!"))
            .ReturnsAsync(false);

        userManager
            .SetupGet(x => x.SupportsUserLockout)
            .Returns(true);

        userManager
            .Setup(x => x.GetLockoutEnabledAsync(user))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.AccessFailedAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        await using var dbContext = CreateDbContext();

        var jwtTokenGenerator = new Mock<IJwtTokenGenerator>();

        var authService =
            CreateAuthService(
                userManager,
                dbContext,
                jwtTokenGenerator:
                    jwtTokenGenerator);

        var request =
            new LoginRequest
            {
                Email = "student@test.com",
                Password = "WrongPassword123!"
            };

        // Act
        var action =
            async () => await authService.LoginAsync(request);

        // Assert
        var exception =
            await Assert.
                ThrowsAsync<InvalidCredentialsException>(action);

        Assert.Equal( "Invalid email or password.",exception.Message);

        userManager.Verify(
            x => x.AccessFailedAsync(user),Times.Once);

        jwtTokenGenerator.Verify(
            x => x.Generate(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Never);
    }

    [Fact]
    public async Task Login_WhenEmailIsNotConfirmed_ShouldResetFailedAttemptsAndThrowEmailNotConfirmedException()
    {
        // Arrange
        var user =
            new AppUser
            {
                Id = "user-123",
                Email = "student@test.com",
                DisplayName = "Student User"
            };

        var userManager =
            CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync("student@test.com"))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.CheckPasswordAsync(user,"Password123!"))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false);

        userManager
            .SetupGet(x => x.SupportsUserLockout)
            .Returns(true);

        userManager
            .Setup(x => x.ResetAccessFailedCountAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        userManager
            .Setup(x =>x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(false);

        await using var dbContext = CreateDbContext();

        var jwtTokenGenerator = new Mock<IJwtTokenGenerator>();

        var authService =
            CreateAuthService(
                userManager,
                dbContext,
                jwtTokenGenerator:
                    jwtTokenGenerator);

        var request =
            new LoginRequest
            {
                Email = "student@test.com",
                Password = "Password123!"
            };

        // Act
        var action =
            async () => await authService.LoginAsync(request);

        // Assert
        var exception =
            await Assert.
                ThrowsAsync<EmailNotConfirmedException>(action);

        Assert.Equal(
            "Email confirmation is required before login.",exception.Message);

        userManager.Verify(
            x => x.ResetAccessFailedCountAsync(user),
            Times.Once);

        userManager.Verify(
            x => x.GetRolesAsync(user),
            Times.Never);

        jwtTokenGenerator.Verify(
            x => x.Generate(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Never);
    }

    [Fact]
    public async Task Login_WhenAccountIsLocked_ShouldThrowAccountLockedException()
    {
        // Arrange
        var user =
            new AppUser
            {
                Id = "user-123",
                Email = "student@test.com",
                DisplayName = "Student User"
            };

        var lockedUntil =
            DateTimeOffset.UtcNow.AddMinutes(10);

        var userManager = CreateMockUserManager();

        userManager
            .Setup(x => x.FindByEmailAsync( "student@test.com"))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.CheckPasswordAsync(user, "Password123!"))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.GetLockoutEndDateAsync(user))
            .ReturnsAsync(lockedUntil);

        await using var dbContext = CreateDbContext();

        var jwtTokenGenerator =
            new Mock<IJwtTokenGenerator>();

        var authService =
            CreateAuthService(
                userManager,
                dbContext,
                jwtTokenGenerator:
                    jwtTokenGenerator);

        var request =
            new LoginRequest
            {
                Email = "student@test.com",
                Password = "Password123!"
            };

        // Act
        var action =
            async () => await authService.LoginAsync(request);

        // Assert
        var exception =
            await Assert
                .ThrowsAsync<AccountLockedException>(action);

        Assert.Equal(
               lockedUntil,
               exception.LockedUntilUtc
            );

        userManager.Verify(
            x => x.ResetAccessFailedCountAsync(user),
            Times.Never);

        userManager.Verify(
            x => x.IsEmailConfirmedAsync(user),
            Times.Never);

        userManager.Verify(
            x => x.GetRolesAsync(user),
            Times.Never);

        jwtTokenGenerator.Verify(
            x => x.Generate(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Never);
    }

    [Fact]
    public async Task Login_WhenCredentialsAreValid_ShouldReturnLoginResponseWithToken()
    {
        // Arrange
        const string email = "student@test.com";
        const string password = "Password123!";

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = email,
            UserName = email,
            DisplayName = "Test Student",
            EmailConfirmed = true
        };

        var userManager = new Mock<UserManager<AppUser>>(
            Mock.Of<IUserStore<AppUser>>(),
            null!,
            null!,
            null!,
            null!,
            null!,
            null!,
            null!,
            null!);

        userManager
            .Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.CheckPasswordAsync(user, password))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false);

        userManager
            .Setup(x => x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "Student" });

        userManager
            .Setup(x => x.ResetAccessFailedCountAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        // Fixed JWT expiration
        var jwtExpiresAtUtc = new DateTime(
            2030, 1, 1, 0, 15, 0, DateTimeKind.Utc);

        var jwtToken = new JwtTokenResult(
            "fake-jwt-token",
            jwtExpiresAtUtc);

        var jwtTokenGenerator = new Mock<IJwtTokenGenerator>();

        jwtTokenGenerator
            .Setup(x => x.Generate(
                user.Id,
                email,
                It.IsAny<IReadOnlyCollection<string>>()))
            .Returns(jwtToken);

        // Fixed refresh-token expiration
        var refreshExpiresAtUtc = new DateTime(
            2030, 1, 8, 0, 0, 0, DateTimeKind.Utc);

        var refreshSessionIssuer = new Mock<IRefreshSessionIssuer>();

        refreshSessionIssuer
            .Setup(x => x.CreateAsync(
                user.Id,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new CreatedRefreshSession(
                "fake-refresh-token",
                refreshExpiresAtUtc));

        // Test database
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

        // Create service
        var service = CreateAuthService(
            userManager,
            dbContext,
            jwtTokenGenerator: jwtTokenGenerator,
            refreshSessionIssuer: refreshSessionIssuer);

        var request = new LoginRequest
        {
            Email = email,
            Password = password
        };

        // Act
        var result = await service.LoginAsync(request);

        // Assert: Login response
        Assert.NotNull(result);
        Assert.NotNull(result.Response);

        var response = result.Response;

        Assert.Equal("fake-jwt-token", response.AccessToken);
        Assert.Equal(jwtToken.ExpiresAtUtc, response.ExpiresAtUtc);
        Assert.Equal(user.Id, response.UserId);
        Assert.Equal(email, response.Email);
        Assert.Equal(user.DisplayName, response.DisplayName);
        Assert.Contains("Student", response.Roles);

        // Assert: Refresh session
        Assert.NotNull(result.RefreshSession);

        Assert.Equal(
            "fake-refresh-token",
            result.RefreshSession.RawToken);

        Assert.Equal(
            refreshExpiresAtUtc,
            result.RefreshSession.ExpiresAtUtc);

        // Verify JWT generation
        jwtTokenGenerator.Verify(
            x => x.Generate(
                user.Id,
                email,
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Once);

        // Verify refresh-session issuance
        refreshSessionIssuer.Verify(
            x => x.CreateAsync(
                user.Id,
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Refresh_WhenTokenIsValid_ShouldGenerateJwtAndRotateSession()
    {
        // Arrange
        const string rawToken = "original-refresh-token";
        const string newRawToken = "replacement-refresh-token";
        const string email = "student@test.com";

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = email,
            Email = email,
            DisplayName = "Test Student",
            EmailConfirmed = true
        };

        var userManager = CreateRefreshUserManager();

        userManager
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false);

        userManager
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "Student" });

        var jwtExpiration = new DateTime(
            2030, 1, 1, 0, 15, 0, DateTimeKind.Utc);

        var refreshExpiration = new DateTime(
            2030, 1, 8, 0, 0, 0, DateTimeKind.Utc);

        var executionOrder = new List<string>();

        var jwtGenerator = new Mock<IJwtTokenGenerator>();

        jwtGenerator
            .Setup(x => x.Generate(
                user.Id,
                email,
                It.IsAny<IReadOnlyCollection<string>>()))
            .Callback(() => executionOrder.Add("GenerateJwt"))
            .Returns(new JwtTokenResult(
                "new-access-token",
                jwtExpiration));

        var rotator = new Mock<IRefreshSessionRotator>();

        rotator
            .Setup(x => x.InspectAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(user.Id);

        rotator
            .Setup(x => x.RotateAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .Callback(() => executionOrder.Add("RotateToken"))
            .ReturnsAsync(new RotatedRefreshSession(
                user.Id,
                new CreatedRefreshSession(
                    newRawToken,
                    refreshExpiration)));

        await using var dbContext = CreateRefreshTestDbContext();

        var service = CreateAuthService(
            userManager,
            dbContext,
            jwtTokenGenerator: jwtGenerator,
            refreshSessionRotator: rotator);

        // Act
        var result = await service.RefreshAsync(rawToken);

        // Assert
        Assert.NotNull(result);

        Assert.Equal("new-access-token", result.Response.AccessToken);
        Assert.Equal(jwtExpiration, result.Response.ExpiresAtUtc);
        Assert.Equal(user.Id, result.Response.UserId);
        Assert.Equal(email, result.Response.Email);
        Assert.Equal(user.DisplayName, result.Response.DisplayName);
        Assert.Contains("Student", result.Response.Roles);

        Assert.Equal(
            newRawToken,
            result.RefreshSession.RawToken);

        Assert.Equal(
            refreshExpiration,
            result.RefreshSession.ExpiresAtUtc);

        // JWT generation must occur before rotation.
        Assert.Collection(
            executionOrder,
            step => Assert.Equal("GenerateJwt", step),
            step => Assert.Equal("RotateToken", step));

        rotator.Verify(
            x => x.InspectAsync(
                rawToken,
                It.IsAny<CancellationToken>()),
            Times.Once);

        rotator.Verify(
            x => x.RotateAsync(
                rawToken,
                It.IsAny<CancellationToken>()),
            Times.Once);

        jwtGenerator.Verify(
            x => x.Generate(
                user.Id,
                email,
                It.Is<IReadOnlyCollection<string>>(
                    roles => roles.Contains("Student"))),
            Times.Once);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task Refresh_WhenAccountIsNotEligible_ShouldNotRotateSession(bool emailConfirmed, bool locked)
    {
        // Arrange
        const string rawToken = "original-refresh-token";
        const string email = "student@test.com";

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = email,
            Email = email,
            DisplayName = "Test Student",
            EmailConfirmed = emailConfirmed
        };

        var userManager = CreateRefreshUserManager();

        userManager
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(emailConfirmed);

        userManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(locked);

        var rotator = new Mock<IRefreshSessionRotator>();

        rotator
            .Setup(x => x.InspectAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(user.Id);

        var jwtGenerator = new Mock<IJwtTokenGenerator>();

        await using var dbContext = CreateRefreshTestDbContext();

        var service = CreateAuthService(
            userManager,
            dbContext,
            jwtTokenGenerator: jwtGenerator,
            refreshSessionRotator: rotator);

        // Act
        var result = await service.RefreshAsync(rawToken);

        // Assert
        Assert.Null(result);

        rotator.Verify(
            x => x.RotateAsync(
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()),
            Times.Never);

        jwtGenerator.Verify(
            x => x.Generate(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Never);

        userManager.Verify(
            x => x.GetRolesAsync(user),
            Times.Never);
    }

    [Fact]
    public async Task Refresh_WhenUserDoesNotExist_ShouldNotRotateSession()
    {
        // Arrange
        const string rawToken = "original-refresh-token";

        var userId = Guid.NewGuid().ToString();

        var userManager = CreateRefreshUserManager();

        userManager
            .Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync((AppUser?)null);

        var rotator = new Mock<IRefreshSessionRotator>();

        rotator
            .Setup(x => x.InspectAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);

        var jwtGenerator = new Mock<IJwtTokenGenerator>();

        await using var dbContext = CreateRefreshTestDbContext();

        var service = CreateAuthService(
            userManager,
            dbContext,
            jwtTokenGenerator: jwtGenerator,
            refreshSessionRotator: rotator);

        // Act
        var result = await service.RefreshAsync(rawToken);

        // Assert
        Assert.Null(result);

        userManager.Verify(
            x => x.FindByIdAsync(userId),
            Times.Once);

        rotator.Verify(
            x => x.RotateAsync(
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()),
            Times.Never);

        jwtGenerator.Verify(
            x => x.Generate(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Never);
    }

    [Fact]
    public async Task Refresh_WhenJwtGenerationFails_ShouldNotRotateSession()
    {
        // Arrange
        const string rawToken = "original-refresh-token";
        const string email = "student@test.com";

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = email,
            Email = email,
            DisplayName = "Test Student",
            EmailConfirmed = true
        };

        var userManager = CreateRefreshUserManager();

        userManager
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false);

        userManager
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "Student" });

        var rotator = new Mock<IRefreshSessionRotator>();

        rotator
            .Setup(x => x.InspectAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(user.Id);

        var jwtGenerator = new Mock<IJwtTokenGenerator>();

        jwtGenerator
            .Setup(x => x.Generate(
                user.Id,
                email,
                It.IsAny<IReadOnlyCollection<string>>()))
            .Throws(new InvalidOperationException(
                "JWT generation failed"));

        await using var dbContext = CreateRefreshTestDbContext();

        var service = CreateAuthService(
            userManager,
            dbContext,
            jwtTokenGenerator: jwtGenerator,
            refreshSessionRotator: rotator);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.RefreshAsync(rawToken));

        // No replacement session should be created.
        rotator.Verify(
            x => x.RotateAsync(
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Refresh_WhenTokenIsInvalid_ShouldReturnNull()
    {
        // Arrange
        const string rawToken = "invalid-refresh-token";

        var userManager = CreateRefreshUserManager();
        var jwtGenerator = new Mock<IJwtTokenGenerator>();
        var rotator = new Mock<IRefreshSessionRotator>();

        rotator
            .Setup(x => x.InspectAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        await using var dbContext = CreateRefreshTestDbContext();

        var service = CreateAuthService(
            userManager,
            dbContext,
            jwtTokenGenerator: jwtGenerator,
            refreshSessionRotator: rotator);

        // Act
        var result = await service.RefreshAsync(rawToken);

        // Assert
        Assert.Null(result);

        userManager.Verify(
            x => x.FindByIdAsync(It.IsAny<string>()),
            Times.Never);

        jwtGenerator.Verify(
            x => x.Generate(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Never);

        rotator.Verify(
            x => x.RotateAsync(
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task Refresh_WhenRotationFails_ShouldReturnNull()
    {
        // Arrange
        const string rawToken = "original-refresh-token";
        const string email = "student@test.com";

        var user = new AppUser
        {
            Id = Guid.NewGuid().ToString(),
            UserName = email,
            Email = email,
            DisplayName = "Test Student",
            EmailConfirmed = true
        };

        var userManager = CreateRefreshUserManager();

        userManager
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        userManager
            .Setup(x => x.IsEmailConfirmedAsync(user))
            .ReturnsAsync(true);

        userManager
            .Setup(x => x.IsLockedOutAsync(user))
            .ReturnsAsync(false);

        userManager
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { "Student" });

        var rotator = new Mock<IRefreshSessionRotator>();

        rotator
            .Setup(x => x.InspectAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(user.Id);

        // Rotation fails because the token is no longer valid.
        rotator
            .Setup(x => x.RotateAsync(
                rawToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((RotatedRefreshSession?)null);

        var jwtGenerator = new Mock<IJwtTokenGenerator>();

        var jwtExpiration = new DateTime(
            2030, 1, 1, 0, 15, 0, DateTimeKind.Utc);

        jwtGenerator
            .Setup(x => x.Generate(
                user.Id,
                email,
                It.IsAny<IReadOnlyCollection<string>>()))
            .Returns(new JwtTokenResult(
                "new-access-token",
                jwtExpiration));

        await using var dbContext = CreateRefreshTestDbContext();

        var service = CreateAuthService(
            userManager,
            dbContext,
            jwtTokenGenerator: jwtGenerator,
            refreshSessionRotator: rotator);

        // Act
        var result = await service.RefreshAsync(rawToken);

        // Assert
        Assert.Null(result);

        jwtGenerator.Verify(
            x => x.Generate(
                user.Id,
                email,
                It.IsAny<IReadOnlyCollection<string>>()),
            Times.Once);

        rotator.Verify(
            x => x.RotateAsync(
                rawToken,
                It.IsAny<CancellationToken>()),
            Times.Once);
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
     Mock<IEmailService>? emailService = null,
     Mock<IJwtTokenGenerator>? jwtTokenGenerator = null,
     Mock<IRefreshSessionIssuer>? refreshSessionIssuer = null,
     Mock<IRefreshSessionRotator>? refreshSessionRotator = null)
    {
        emailService ??= new Mock<IEmailService>();
        jwtTokenGenerator ??= new Mock<IJwtTokenGenerator>();

        // Only configure the default mock if the test
        // hasn't supplied its own refresh-session issuer.
        if (refreshSessionIssuer is null)
        {
            refreshSessionIssuer = new Mock<IRefreshSessionIssuer>();

            var expiresAtUtc = new DateTime(
                2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            refreshSessionIssuer
                .Setup(x => x.CreateAsync(
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(
                    new CreatedRefreshSession(
                        "fake-refresh-token",
                        expiresAtUtc));
        }

        refreshSessionRotator ??= new Mock<IRefreshSessionRotator>();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["Client:BaseUrl"] = "http://localhost:4200"
                })
            .Build();

        var logger = Mock.Of<ILogger<AuthService>>();

        return new AuthService(
            userManager.Object,
            dbContext,
            emailService.Object,
            configuration,
            logger,
            jwtTokenGenerator.Object,
            refreshSessionIssuer.Object,
            refreshSessionRotator.Object);
    }

    private static Mock<UserManager<AppUser>> CreateRefreshUserManager()
    {
        return new Mock<UserManager<AppUser>>(
            Mock.Of<IUserStore<AppUser>>(),
            null!,
            null!,
            null!,
            null!,
            null!,
            null!,
            null!,
            null!);
    }

    private static AlDarDbContext CreateRefreshTestDbContext()
    {
        var options = new DbContextOptionsBuilder<AlDarDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        return new AlDarDbContext(options);
    }
}