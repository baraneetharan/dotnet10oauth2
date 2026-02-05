namespace EnterpriseAuthApi.Models;

public sealed class RefreshTokenRecord
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid UserId { get; init; }
    public string FamilyId { get; init; } = Guid.NewGuid().ToString("N");
    public Guid? ParentTokenId { get; init; }
    public string TokenHash { get; init; } = string.Empty;
    public string TokenSalt { get; init; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; init; }
    public DateTimeOffset ExpiresAtUtc { get; init; }
    public DateTimeOffset AbsoluteExpiresAtUtc { get; init; }
    public DateTimeOffset? RevokedAtUtc { get; set; }
    public Guid? ReplacedByTokenId { get; set; }
    public string? RevocationReason { get; set; }
    public string? CreatedByIpAddress { get; init; }
    public string? UserAgent { get; init; }

    public bool IsActive => RevokedAtUtc is null && DateTimeOffset.UtcNow < ExpiresAtUtc && DateTimeOffset.UtcNow < AbsoluteExpiresAtUtc;
}
