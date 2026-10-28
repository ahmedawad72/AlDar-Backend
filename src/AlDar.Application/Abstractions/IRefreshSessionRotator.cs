using AlDar.Application.Authentication;

namespace AlDar.Application.Abstractions;

public interface IRefreshSessionRotator
{
    Task<string?> InspectAsync(string rawToken, CancellationToken cancellationToken = default);
    Task<RotatedRefreshSession?> RotateAsync(string rawToken,CancellationToken cancellationToken = default);
    Task RevokeAsync(string? rawToken,CancellationToken cancellationToken = default);
}