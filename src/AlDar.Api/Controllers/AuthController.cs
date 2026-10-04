using AlDar.Application.Authentication;
using Azure;
using Microsoft.AspNetCore.Mvc;

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
}