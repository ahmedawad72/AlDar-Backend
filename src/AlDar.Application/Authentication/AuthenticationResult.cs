namespace AlDar.Application.Authentication;

public sealed record AuthenticationResult(LoginResponse Response,CreatedRefreshSession RefreshSession);