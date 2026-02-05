namespace EnterpriseAuthApi.Models;

public sealed record AppUser(
    Guid Id,
    string Username,
    string PasswordHash,
    string Department,
    string[] Roles,
    string[] Permissions,
    bool MfaEnrolled);
