namespace AlDar.Application.Authentication;

public sealed record JwtTokenResult(string AccessToken,DateTimeOffset ExpiresAtUtc);