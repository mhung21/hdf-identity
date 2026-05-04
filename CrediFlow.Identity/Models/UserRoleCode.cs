namespace CrediFlow.Identity.Models;

/// <summary>
/// User role codes matching database enum user_role_code
/// </summary>
public enum UserRoleCode
{
    ADMIN,
    REGIONAL_MANAGER,
    STORE_MANAGER,
    STAFF
}

/// <summary>
/// Extension methods for UserRoleCode enum
/// </summary>
public static class UserRoleCodeExtensions
{
    /// <summary>
    /// Check if role can create users for any store
    /// </summary>
    public static bool CanCreateAnyStoreUser(this UserRoleCode role)
    {
        return role == UserRoleCode.ADMIN;
    }

    /// <summary>
    /// Check if role can create users for their own store
    /// </summary>
    public static bool CanCreateOwnStoreUser(this UserRoleCode role)
    {
        return role == UserRoleCode.STORE_MANAGER;
    }

    /// <summary>
    /// Check if role can create users at all
    /// </summary>
    public static bool CanCreateUser(this UserRoleCode role)
    {
        return role == UserRoleCode.ADMIN || role == UserRoleCode.STORE_MANAGER || role == UserRoleCode.REGIONAL_MANAGER;
    }

    /// <summary>
    /// Get display name for role
    /// </summary>
    public static string GetDisplayName(this UserRoleCode role)
    {
        return role switch
        {
            UserRoleCode.ADMIN => "System Administrator",
            UserRoleCode.REGIONAL_MANAGER => "Regional Manager",
            UserRoleCode.STORE_MANAGER => "Store Manager",
            UserRoleCode.STAFF => "Staff Member",
            _ => role.ToString()
        };
    }
}