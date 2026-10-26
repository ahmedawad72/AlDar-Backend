namespace AlDar.Infrastructure.Authentication;

public sealed class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string UserId { get; set; } = string.Empty;

    public Guid FamilyId { get; set; }

    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    public DateTime ExpiresAtUtc { get; set; }

    public DateTime AbsoluteExpiresAtUtc { get; set; }

    public DateTime? ConsumedAtUtc { get; set; }

    public DateTime? RevokedAtUtc { get; set; }
}