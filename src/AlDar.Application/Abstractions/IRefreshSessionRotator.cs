using AlDar.Application.Authentication;

namespace AlDar.Application.Abstractions;

public interface IRefreshSessionRotator
{
    Task<RotatedRefreshSession?> RotateAsync(string rawToken,CancellationToken cancellationToken = default);
}