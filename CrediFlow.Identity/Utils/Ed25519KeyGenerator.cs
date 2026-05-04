using System.Security.Cryptography;

namespace CrediFlow.Identity.Utils;

/// <summary>
/// Utility to generate ES256 (ECDSA P-256) key pairs for JWT signing
/// ES256 = ECDSA with P-256 curve and SHA-256 (well-known JWT algorithm)
/// </summary>
public static class EcdsaKeyGenerator
{
    /// <summary>
    /// Generate a new ES256 (ECDSA P-256) key pair
    /// Returns (PrivateKeyBase64, PublicKeyBase64)
    /// </summary>
    public static (string PrivateKey, string PublicKey) GenerateKeyPair()
    {
        // Create ECDSA with P-256 curve (secp256r1/prime256v1)
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        
        // Export keys in standard formats
        var privateKeyBytes = ecdsa.ExportPkcs8PrivateKey();
        var publicKeyBytes = ecdsa.ExportSubjectPublicKeyInfo();
        
        // Convert to Base64 for storage in config
        var privateKeyBase64 = Convert.ToBase64String(privateKeyBytes);
        var publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
        
        return (privateKeyBase64, publicKeyBase64);
    }

    /// <summary>
    /// Generate key pair and print to console for configuration
    /// </summary>
    public static void GenerateAndPrintKeys()
    {
        var (privateKey, publicKey) = GenerateKeyPair();
        
        Console.WriteLine("========================================");
        Console.WriteLine("ES256 (ECDSA P-256) Key Pair Generated");
        Console.WriteLine("========================================");
        Console.WriteLine();
        Console.WriteLine("Add these to your appsettings.json:");
        Console.WriteLine();
        Console.WriteLine("\"JwtSettings\": {");
        Console.WriteLine($"  \"EcdsaPrivateKey\": \"{privateKey}\",");
        Console.WriteLine($"  \"EcdsaPublicKey\": \"{publicKey}\",");
        Console.WriteLine("  \"Issuer\": \"https://quanly.hdfinanceco.vn\",");
        Console.WriteLine("  \"Audience\": \"hdf.api.identity\",");
        Console.WriteLine("  ... (other settings)");
        Console.WriteLine("}");
        Console.WriteLine();
        Console.WriteLine("========================================");
        Console.WriteLine("SECURITY NOTES:");
        Console.WriteLine("- Keep EcdsaPrivateKey SECRET (only on identity service)");
        Console.WriteLine("- EcdsaPublicKey can be shared with other services to verify tokens");
        Console.WriteLine("- Algorithm: ES256 (ECDSA P-256 + SHA-256)");
        Console.WriteLine($"- Private key length: {privateKey.Length} chars");
        Console.WriteLine($"- Public key length: {publicKey.Length} chars");
        Console.WriteLine("- Token signature: 64 bytes (vs 32+ bytes with HMAC-SHA256)");
        Console.WriteLine("========================================");
    }

    /// <summary>
    /// Load ECDsa from Base64 private key for signing
    /// </summary>
    public static ECDsa LoadPrivateKey(string privateKeyBase64)
    {
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
        return ecdsa;
    }

    /// <summary>
    /// Load ECDsa from Base64 public key for verification
    /// </summary>
    public static ECDsa LoadPublicKey(string publicKeyBase64)
    {
        var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
        return ecdsa;
    }
}
