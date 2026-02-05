using EnterpriseAuthApi.Models;
using EnterpriseAuthApi.Security;

namespace EnterpriseAuthApi.Data;

public interface IUserStore
{
    AppUser? GetByUsername(string username);
    AppUser? GetById(Guid userId);
}

public sealed class InMemoryUserStore : IUserStore
{
    private readonly Dictionary<string, AppUser> _users;

    public InMemoryUserStore(IPasswordHasher passwordHasher)
    {
        _users = new(StringComparer.OrdinalIgnoreCase)
        {
            ["admin"] = new AppUser(
                Guid.Parse("11111111-1111-1111-1111-111111111111"),
                "admin",
                passwordHasher.HashPassword("Admin!ChangeMe1"),
                "Security",
                ["Administrator"],
                ["users:manage", "finance:read", "finance:write", "hr:read"],
                true),
            ["analyst"] = new AppUser(
                Guid.Parse("22222222-2222-2222-2222-222222222222"),
                "analyst",
                passwordHasher.HashPassword("Analyst!ChangeMe1"),
                "Finance",
                ["Analyst"],
                ["finance:read"],
                false)
        };
    }

    public AppUser? GetByUsername(string username)
        => _users.GetValueOrDefault(username);

    public AppUser? GetById(Guid userId)
        => _users.Values.FirstOrDefault(u => u.Id == userId);
}
