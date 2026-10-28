namespace AlDar.Infrastructure.Authentication;

public sealed class RefreshSessionOptions
{
    public const string SectionName = "RefreshSession";

    public int TokenLifetimeDays { get; set; } = 7;

    public int MaxSessionLifetimeDays { get; set; } = 30;
}