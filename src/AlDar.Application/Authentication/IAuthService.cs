namespace AlDar.Application.Authentication;

public interface IAuthService
{
    Task<RegisterResponse> RegisterAsync(RegisterRequest request);
    Task ConfirmEmailAsync( ConfirmEmailRequest request);
    Task<bool> ResendConfirmationEmailAsync(ResendConfirmationEmailRequest request);
}