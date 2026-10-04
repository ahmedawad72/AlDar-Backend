namespace AlDar.Application.Authentication;

public sealed class ResendConfirmationEmailRequest
{
    public string Email { get; set; } = string.Empty;
}