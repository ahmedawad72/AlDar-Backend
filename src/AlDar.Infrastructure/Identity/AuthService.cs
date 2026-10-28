using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Application.Exceptions;
using AlDar.Domain.Constants;
using AlDar.Infrastructure.Authentication;
using AlDar.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Text.Encodings.Web;

namespace AlDar.Infrastructure.Identity;

public sealed class AuthService : IAuthService
{
    private readonly UserManager<AppUser> _userManager;
    private readonly AlDarDbContext _dbContext;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthService> _logger;
    private readonly IJwtTokenGenerator _jwtTokenGenerator;
    private readonly IRefreshSessionIssuer _refreshSessionIssuer;
    private readonly IRefreshSessionRotator _refreshSessionRotator;

    public AuthService(
        UserManager<AppUser> userManager,
        AlDarDbContext dbContext,
        IEmailService emailService,
        IConfiguration configuration,
        ILogger<AuthService> logger,
        IJwtTokenGenerator jwtTokenGenerator,
        IRefreshSessionIssuer refreshSessionIssuer,
        IRefreshSessionRotator refreshSessionRotator)
    {
        _userManager = userManager;
        _dbContext = dbContext;
        _emailService = emailService;
        _configuration = configuration;
        _logger = logger;
        _jwtTokenGenerator = jwtTokenGenerator;
        _refreshSessionIssuer = refreshSessionIssuer;
        _refreshSessionRotator = refreshSessionRotator;
    }

    public async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
    {
        await EnsureEmailIsAvailableAsync(request.Email);

        ValidateRegistrationRole(request.Role);

        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync();

        var user = await CreateUserAsync(request);

        await AssignRoleAsync(user, request.Role);

        await transaction.CommitAsync();

        var confirmationEmailSent =
            await TrySendConfirmationEmailAsync(user);

        return CreateRegisterResponse(
            user,
            request.Role,
            confirmationEmailSent);
    }

    public async Task ConfirmEmailAsync(ConfirmEmailRequest request)
    {
        var user =
            await _userManager.FindByIdAsync(request.UserId);

        if (user is null)
        {
            throw InvalidConfirmationLink();
        }

        if (await _userManager.IsEmailConfirmedAsync(user))
        {
            return;
        }

        var result =
            await _userManager.ConfirmEmailAsync(
                user,
                request.Token);

        if (!result.Succeeded)
        {
            throw InvalidConfirmationLink();
        }
    }

    public async Task<bool> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request)
    {
        var user =
            await _userManager.FindByEmailAsync(
                request.Email);

        if (user is null)
        {
            return true;
        }

        var alreadyConfirmed =
            await _userManager.IsEmailConfirmedAsync(user);

        if (alreadyConfirmed)
        {
            return true;
        }

        return await TrySendConfirmationEmailAsync(user);
    }

    public async Task<AuthenticationResult> LoginAsync(LoginRequest request)
    {
        ValidateLoginRequest(request);

        var user =
            await _userManager.FindByEmailAsync(request.Email);

        if (user is null)
            throw new InvalidCredentialsException();

        var passwordIsValid =
            await _userManager.CheckPasswordAsync(user,request.Password);

        if (!passwordIsValid)
        {
            await RecordFailedLoginAttemptAsync(user);

            throw new InvalidCredentialsException();
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockedUntil =
                await _userManager.GetLockoutEndDateAsync(user);

            throw new AccountLockedException(lockedUntil);
        }

        await ResetFailedLoginAttemptsAsync(user);

        var emailIsConfirmed =
            await _userManager.IsEmailConfirmedAsync(user);

        if (!emailIsConfirmed)
            throw new EmailNotConfirmedException();

        var roles =
            await _userManager.GetRolesAsync(user);

        var roleClaims = roles.ToArray();

        var token =
            _jwtTokenGenerator.Generate(user.Id,user.Email!,roleClaims);

        var loginResponse = new LoginResponse
        {
            AccessToken = token.AccessToken,
            ExpiresAtUtc = token.ExpiresAtUtc,
            UserId = user.Id,
            Email = user.Email!,
            DisplayName = user.DisplayName,
            Roles = roleClaims
        };

        var refreshSession = await _refreshSessionIssuer.CreateAsync(user.Id);

        return new AuthenticationResult(loginResponse, refreshSession);
    }

    public async Task<AuthenticationResult?> RefreshAsync(string rawToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
            return null;

        // 1. Validate the refresh token and retrieve its UserId.
        // The token is not consumed here.
        var userId = await _refreshSessionRotator.InspectAsync(
            rawToken, cancellationToken);

        if (userId is null)
            return null;

        // 2. Retrieve the current user.
        var user = await _userManager.FindByIdAsync(userId);

        if (user is null || string.IsNullOrWhiteSpace(user.Email))
            return null;

        // 3. Verify the account is allowed to authenticate.
        if (!await _userManager.IsEmailConfirmedAsync(user))
            return null;

        if (await _userManager.IsLockedOutAsync(user))
            return null;

        // 4. Retrieve current roles from Identity.
        var roles = await _userManager.GetRolesAsync(user);
        var roleClaims = roles.ToArray();

        // 5. Generate a fresh JWT in memory.
        var token = _jwtTokenGenerator.Generate(user.Id, user.Email, roleClaims);

        // 6. Rotate the refresh token LAST.
        // Atomically consume the old token and save its replacement.
        var rotatedSession = await _refreshSessionRotator.RotateAsync(rawToken, cancellationToken);

        if (rotatedSession is null)
            return null;

        // 7. Build the public response.
        var response = new LoginResponse
        {
            AccessToken = token.AccessToken,
            ExpiresAtUtc = token.ExpiresAtUtc,
            UserId = user.Id,
            Email = user.Email,
            DisplayName = user.DisplayName,
            Roles = roleClaims
        };

        return new AuthenticationResult(response, rotatedSession.RefreshSession);
    }

    public Task LogoutAsync(string? rawToken, CancellationToken cancellationToken = default)
    {
        return _refreshSessionRotator.RevokeAsync( rawToken,cancellationToken);
    }


    // ============================= Private Methods =============================

    private async Task EnsureEmailIsAvailableAsync( string email)
    {
        var existingUser =
            await _userManager.FindByEmailAsync(email);

        if (existingUser is not null)
        {
            throw new ConflictException(
                "An account with this email already exists.");
        }
    }

    private static void ValidateRegistrationRole(string role)
    {
        if (role == Roles.Student ||
            role == Roles.Teacher)
        {
            return;
        }

        throw new ValidationException(
            new Dictionary<string, string[]>
            {
                ["Role"] =
                [
                    $"Role must be either '{Roles.Student}' or '{Roles.Teacher}'."
                ]
            });
    }

    private async Task<AppUser> CreateUserAsync(RegisterRequest request)
    {
        var user = new AppUser
        {
            Email = request.Email,
            UserName = request.Email,
            DisplayName = request.DisplayName
        };

        var result =
            await _userManager.CreateAsync(
                user,
                request.Password);

        if (!result.Succeeded)
        {
            throw new ValidationException(
                ConvertIdentityErrors(result));
        }

        return user;
    }

    private async Task AssignRoleAsync(AppUser user,string role)
    {
        var result =
            await _userManager.AddToRoleAsync(
                user,
                role);

        if (!result.Succeeded)
        {
            throw new ValidationException(
                ConvertIdentityErrors(result));
        }
    }

    private async Task<bool> TrySendConfirmationEmailAsync(AppUser user)
    {
        var confirmationToken =
            await _userManager
                .GenerateEmailConfirmationTokenAsync(user);

        var confirmationLink =
            BuildConfirmationLink(
                user.Id,
                confirmationToken);

        var safeDisplayName =
            HtmlEncoder.Default.Encode(
                user.DisplayName);

        var safeConfirmationLink =
            HtmlEncoder.Default.Encode(
                confirmationLink);

        var htmlBody =
            BuildConfirmationEmailBody(
                safeDisplayName,
                safeConfirmationLink);

        try
        {
            await _emailService.SendAsync(
                user.Email!,
                "Confirm your AlDar account",
                htmlBody);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to send confirmation email to user {UserId}",
                user.Id);

            return false;
        }
    }

    private string BuildConfirmationLink(string userId,string confirmationToken)
    {
        var clientBaseUrl =
            _configuration["Client:BaseUrl"]
            ?? throw new InvalidOperationException(
                "Client BaseUrl is not configured.");

        return
            $"{clientBaseUrl.TrimEnd('/')}/confirm-email" +
            $"?userId={Uri.EscapeDataString(userId)}" +
            $"&token={Uri.EscapeDataString(confirmationToken)}";
    }

    private static string BuildConfirmationEmailBody(string displayName,string confirmationLink)
    {
        return $"""
            <h2>Welcome to AlDar, {displayName}!</h2>

            <p>
                Please confirm your email address to activate your account.
            </p>

            <p>
                <a href="{confirmationLink}">
                    Confirm email
                </a>
            </p>

            <p>
                If you didn't create this account, you can ignore this email.
            </p>
            """;
    }

    private static RegisterResponse
        CreateRegisterResponse(AppUser user,string role, bool confirmationEmailSent)
    {
        return new RegisterResponse
        {
            Id = user.Id,
            Email = user.Email!,
            DisplayName = user.DisplayName,
            Role = role,
            ConfirmationEmailSent = confirmationEmailSent
        };
    }

    private static Dictionary<string, string[]>  ConvertIdentityErrors(IdentityResult result)
    {
        return result.Errors
            .GroupBy(error => error.Code)
            .ToDictionary(
                group => group.Key,
                group => group
                    .Select(error => error.Description)
                    .ToArray());
    }

    private static ValidationException InvalidConfirmationLink()
    {
        return new ValidationException(
            new Dictionary<string, string[]>
            {
                ["Confirmation"] =
                [
                    "The email confirmation link is invalid or has expired."
                ]
            });
    }

    private static void ValidateLoginRequest(LoginRequest request)
    {
        var errors =
            new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Email))
        {
            errors["Email"] =
            [
                "Email is required."
            ];
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            errors["Password"] =
            [
                "Password is required."
            ];
        }

        if (errors.Count > 0)
            throw new ValidationException(errors);
    }

    private async Task RecordFailedLoginAttemptAsync(AppUser user)
    {
        if (!_userManager.SupportsUserLockout)
            return;

        var lockoutEnabled =
            await _userManager.GetLockoutEnabledAsync(user);

        if (!lockoutEnabled)
            return;

        var result =
            await _userManager.AccessFailedAsync(user);

        if (!result.Succeeded)
        {
            _logger.LogWarning(
                "Failed to record unsuccessful login attempt for user {UserId}",user.Id);
        }
    }

    private async Task ResetFailedLoginAttemptsAsync(AppUser user)
    {
        if (!_userManager.SupportsUserLockout)
            return;

        var result =
            await _userManager.ResetAccessFailedCountAsync(user);

        if (!result.Succeeded)
        {
            _logger.LogWarning(
                "Failed to reset unsuccessful login attempts for user {UserId}",
                user.Id);
        }
    }
}