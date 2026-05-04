using CrediFlow.Identity.Utils;
using Microsoft.AspNetCore.Mvc;

namespace CrediFlow.Identity.Controllers;

/// <summary>
/// Development-only controller for generating ES256 key pairs
/// </summary>
[ApiController]
[Route("api/dev")]
public class DevController : ControllerBase
{
    private readonly IHostEnvironment _environment;

    public DevController(IHostEnvironment environment)
    {
        _environment = environment;
    }

    /// <summary>
    /// Generate ES256 (ECDSA P-256) key pair for JWT signing
    /// Only available in Development environment
    /// </summary>
    /// <returns>ECDSA key pair in Base64 format</returns>
    [HttpGet("generate-keys")]
    public IActionResult GenerateEcdsaKeys()
    {
        // Only allow in Development
        if (!_environment.IsDevelopment())
        {
            return NotFound();
        }

        var (privateKey, publicKey) = EcdsaKeyGenerator.GenerateKeyPair();

        return Ok(new
        {
            Algorithm = "ES256 (ECDSA P-256 + SHA-256)",
            Message = "Add these keys to your appsettings.json under JwtSettings section",
            Keys = new
            {
                EcdsaPrivateKey = privateKey,
                EcdsaPublicKey = publicKey
            },
            SecurityNotes = new[]
            {
                "⚠️ Keep EcdsaPrivateKey SECRET - only on identity service",
                "✓ EcdsaPublicKey can be shared with other services for token verification",
                $"Private key length: {privateKey.Length} characters",
                $"Public key length: {publicKey.Length} characters",
                "Signature size: 64 bytes (compact and secure)"
            },
            ExampleConfiguration = new
            {
                JwtSettings = new
                {
                    EcdsaPrivateKey = privateKey,
                    EcdsaPublicKey = publicKey,
                    Issuer = "CrediFlow.Identity",
                    Audience = "CrediFlow.API",
                    AccessTokenExpirationMinutes = 15,
                    RefreshTokenExpirationDays = 7,
                    MaxFailedLoginAttempts = 5,
                    LockoutDurationMinutes = 30
                }
            }
        });
    }
}
