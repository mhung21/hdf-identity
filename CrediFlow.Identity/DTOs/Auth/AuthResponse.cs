

using static CrediFlow.Common.Utils.Consts;

namespace CrediFlow.Identity.DTOs.Auth;

public class AuthResponse
{
    public Guid UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public UserRoleCode RoleCode { get; set; }
    public string RoleCodeString => RoleCode.ToString();
    public Guid? StoreId { get; set; }
    public string? StoreName { get; set; }

    /// <summary>
    /// JWT Access Token (short-lived, 15 minutes)
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Refresh Token (long-lived, 7 days)
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Access token expiration time in UTC
    /// </summary>
    public DateTime AccessTokenExpiresAt { get; set; }

    /// <summary>
    /// Refresh token expiration time in UTC
    /// </summary>
    public DateTime RefreshTokenExpiresAt { get; set; }

    /// <summary>
    /// User permissions
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Flag indicating if user must change password
    /// </summary>
    public bool MustChangePassword { get; set; }
}
