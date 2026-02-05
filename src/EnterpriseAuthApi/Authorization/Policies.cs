using Microsoft.AspNetCore.Authorization;

namespace EnterpriseAuthApi.Authorization;

public static class Policies
{
    public const string RequireAdministrator = "RequireAdministrator";
    public const string FinanceRead = "FinanceRead";
    public const string FinanceWrite = "FinanceWrite";
    public const string HrRead = "HrRead";
    public const string ManageUsers = "ManageUsers";
    public const string MfaRequired = "MfaRequired";

    public static void AddEnterprisePolicies(AuthorizationOptions options)
    {
        options.AddPolicy(RequireAdministrator, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole("Administrator");
        });

        options.AddPolicy(FinanceRead, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireClaim("permission", "finance:read");
        });

        options.AddPolicy(FinanceWrite, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireClaim("permission", "finance:write");
            policy.RequireClaim("department", "Finance", "Security");
        });

        options.AddPolicy(HrRead, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireClaim("permission", "hr:read");
        });

        options.AddPolicy(ManageUsers, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireClaim("permission", "users:manage");
        });

        options.AddPolicy(MfaRequired, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireClaim("mfa", "true");
        });
    }
}
