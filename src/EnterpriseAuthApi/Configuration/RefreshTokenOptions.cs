namespace EnterpriseAuthApi.Configuration;

public sealed class RefreshTokenOptions
{
    public const string SectionName = "RefreshToken";

    public int LifetimeDays { get; init; } = 30;
    public int AbsoluteLifetimeDays { get; init; } = 90;
    public int ReuseDetectionWindowSeconds { get; init; } = 30;
}
