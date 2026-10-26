using AlDar.Application.Authentication;

namespace AlDar.Application.Abstractions;

public interface IRefreshSessionIssuer
{
    Task<CreatedRefreshSession> CreateAsync(string userId, CancellationToken cancellationToken = default);
}