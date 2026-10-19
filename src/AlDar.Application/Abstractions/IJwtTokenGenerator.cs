using AlDar.Application.Authentication;

namespace AlDar.Application.Abstractions;

public interface IJwtTokenGenerator
{
    /* Why don't we pass AppUser?
     * AppUser belongs to:
             AlDar.Infrastructure
     * while the interface belongs to:
             AlDar.Application
     * Application should not depend on Infrastructure.
     * That would reverse our dependency direction.
    */
    JwtTokenResult Generate( string userId, string email, IReadOnlyCollection<string> roles);
}