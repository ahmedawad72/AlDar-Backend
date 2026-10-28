using AlDar.Infrastructure.Authentication;

namespace AlDar.Infrastructure.Tests.Authentication;

public class RefreshTokenSecurityTests
{
    [Fact]
    public void GenerateToken_ShouldReturnDistinctTokens()
    {
        // Act
        var token1 = RefreshTokenSecurity.GenerateToken();
        var token2 = RefreshTokenSecurity.GenerateToken();

        // Assert
        Assert.NotEqual(token1, token2);

        Assert.Matches(
            "^[A-Za-z0-9_-]{43}$",
            token1);
    }

    [Fact]
    public void HashToken_ShouldProduceConsistentHash()
    {
        // Arrange
        var token = RefreshTokenSecurity.GenerateToken();

        // Act
        var hash1 = RefreshTokenSecurity.HashToken(token);
        var hash2 = RefreshTokenSecurity.HashToken(token);

        // Assert
        Assert.Equal(hash1, hash2);
        Assert.Equal(64, hash1.Length);
        Assert.NotEqual(token, hash1);
    }
}