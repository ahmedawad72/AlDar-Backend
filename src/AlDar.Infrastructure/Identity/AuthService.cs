using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using AlDar.Application.Exceptions;
using AlDar.Domain.Constants;
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

    public AuthService(
        UserManager<AppUser> userManager,
        AlDarDbContext dbContext,
        IEmailService emailService,
        IConfiguration configuration,
        ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _dbContext = dbContext;
        _emailService = emailService;
        _configuration = configuration;
        _logger = logger;
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

    private static Dictionary<string, string[]> 
        ConvertIdentityErrors(IdentityResult result)
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
}