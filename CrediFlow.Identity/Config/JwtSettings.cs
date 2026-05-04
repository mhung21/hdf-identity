namespace CrediFlow.Identity.Config;

public class JwtSettings
{
    public const string SectionName = "JwtSettings";

    /// <summary>
    /// ECDSA P-256 private key in Base64 format for signing JWT tokens with ES256
    /// Keep this SECRET - only on identity service
    /// Generate with: EcdsaKeyGenerator.GenerateAndPrintKeys()
    /// </summary>
    public string EcdsaPrivateKey { get; set; } = string.Empty;

    /// <summary>
    /// ECDSA P-256 public key in Base64 format for verifying JWT tokens
    /// Can be safely shared with other microservices for token verification
    /// </summary>
    public string EcdsaPublicKey { get; set; } = string.Empty;

    /// <summary>
    /// LEGACY: Symmetric secret key for HMAC-SHA256 signing
    /// DEPRECATED: Use EcdsaPrivateKey/PublicKey (ES256) for better security
    /// If both are configured, ECDSA takes precedence
    /// </summary>
    public string SecretKey { get; set; } = string.Empty;

    /// <summary>
    /// Token issuer (e.g., "CrediFlow.Identity")
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// Token audience (e.g., "CrediFlow.API")
    /// </summary>
    public string Audience { get; set; } = "hdf.api.identity";

    /// <summary>
    /// Access token expiration in minutes (default: 15 minutes)
    /// </summary>
    public int AccessTokenExpirationMinutes { get; set; } = 15;

    /// <summary>
    /// Refresh token expiration in days (default: 7 days)
    /// </summary>
    public int RefreshTokenExpirationDays { get; set; } = 7;

    /// <summary>
    /// Maximum failed login attempts before account lockout
    /// </summary>
    public int MaxFailedLoginAttempts { get; set; } = 5;

    /// <summary>
    /// Account lockout duration in minutes
    /// </summary>
    public int LockoutDurationMinutes { get; set; } = 30;
}
