using AlDar.Application.Abstractions;
using AlDar.Application.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AlDar.Infrastructure.Authentication;

public sealed class JwtTokenGenerator : IJwtTokenGenerator
{
    private readonly JwtOptions _options;

    public JwtTokenGenerator(IOptions<JwtOptions> options)
    {
        _options = options.Value;
    }

    public JwtTokenResult Generate( string userId,string email,IReadOnlyCollection<string> roles)
    {
        var issuedAt = DateTimeOffset.UtcNow;

        var expiresAt = issuedAt.AddMinutes(_options.ExpirationMinutes);

        var claims =new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub,userId),

            new(JwtRegisteredClaimNames.Email,email),

            new(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
        };

        claims.AddRange(
              roles.Select( role => new Claim(ClaimTypes.Role,role))
            );

        var signingKey =
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));

        var signingCredentials =
            new SigningCredentials(signingKey,SecurityAlgorithms.HmacSha256);

        var token =
            new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: issuedAt.UtcDateTime,
                expires: expiresAt.UtcDateTime,
                signingCredentials: signingCredentials);

        var accessToken =
            new JwtSecurityTokenHandler()
                .WriteToken(token);

        return new JwtTokenResult(accessToken,expiresAt);
    }
}