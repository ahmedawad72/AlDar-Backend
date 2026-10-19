namespace AlDar.Application.Authentication;

public sealed class CurrentUserResponse
{
    public string UserId { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public IReadOnlyCollection<string> Roles { get; set; } = [];
}