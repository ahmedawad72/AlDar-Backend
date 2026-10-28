using AlDar.Application.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
namespace AlDar.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

   
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var response = await _authService.RegisterAsync(request);

        return StatusCode(StatusCodes.Status201Created, response);
    }


    [HttpPost("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(ConfirmEmailRequest request)
    {
        await _authService.ConfirmEmailAsync(request);

        return NoContent();
    }

  
    [HttpPost("resend-confirmation-email")]
    public async Task<IActionResult> ResendConfirmationEmail(
        ResendConfirmationEmailRequest request)
    {
        var sent =
            await _authService
                .ResendConfirmationEmailAsync(request);

        if (!sent)
        {
            return Problem(
                statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "Email service unavailable",
                detail:
                    "We couldn't send the confirmation email right now. Please try again later.");
        }

        return NoContent();
    }


    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest request)
    {
        var result = await _authService.LoginAsync(request);
        Response.Cookies.Append(
        "aldar.refresh",
        result.RefreshSession.RawToken,
        new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/auth",
            Expires = new DateTimeOffset(
                result.RefreshSession.ExpiresAtUtc,
                TimeSpan.Zero)
        });

        return Ok(result.Response);
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<ActionResult<LoginResponse>> Refresh( CancellationToken cancellationToken)
    {
        // 1. Read the refresh token from the HttpOnly cookie.
        if (!Request.Cookies.TryGetValue(
                "aldar.refresh", out var rawToken))
        {
            return Unauthorized();
        }

        // 2. Validate the user and rotate the refresh session.
        var result = await _authService.RefreshAsync(
            rawToken,
            cancellationToken);

        if (result is null)
            return Unauthorized();

        // 3. Replace the browser's refresh cookie.
        Response.Cookies.Append(
            "aldar.refresh",
            result.RefreshSession.RawToken,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth",
                Expires = new DateTimeOffset(
                    result.RefreshSession.ExpiresAtUtc,
                    TimeSpan.Zero)
            });

        // 4. Return only the JWT and current user information.
        return Ok(result.Response);
    }

    [HttpPost("logout")]
    [AllowAnonymous]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        // 1. Retrieve the refresh credential, if present.
        Request.Cookies.TryGetValue( "aldar.refresh", out var rawToken);

        // 2. Revoke the session family.
        await _authService.LogoutAsync( rawToken,cancellationToken);

        // 3. Delete the refresh cookie.
        Response.Cookies.Delete(
            "aldar.refresh",
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth"
            });

        // 4. Always return success after processing.
        return NoContent();
    }

    [Authorize]
    [HttpGet("me")]
    public ActionResult<CurrentUserResponse> Me()
    {
        var userId =
            User.FindFirstValue(
                JwtRegisteredClaimNames.Sub);

        var email =
            User.FindFirstValue(
                JwtRegisteredClaimNames.Email);

        var roles =
            User.FindAll(ClaimTypes.Role)
                .Select(claim => claim.Value)
                .ToArray();

        return Ok(
            new CurrentUserResponse
            {
                UserId = userId ?? string.Empty,
                Email = email ?? string.Empty,
                Roles = roles
            });
    }
}