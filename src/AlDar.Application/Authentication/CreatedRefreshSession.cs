namespace AlDar.Application.Authentication;

public sealed record CreatedRefreshSession(string RawToken, DateTime ExpiresAtUtc);