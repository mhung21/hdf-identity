namespace CrediFlow.Identity.Utils;

/// <summary>
/// Tiện ích chuẩn hóa hash mật khẩu cho toàn bộ Identity service.
/// Hệ thống này dùng BCrypt làm chuẩn duy nhất cho password mới.
/// </summary>
public static class PasswordHashing
{
    private const int WorkFactor = 11;

    private static readonly string[] BcryptPrefixes =
    [
        "$2a$",
        "$2b$",
        "$2y$"
    ];

    public static string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: WorkFactor);
    }

    public static bool VerifyPassword(string password, string? passwordHash)
    {
        if (!IsBcryptHash(passwordHash))
        {
            return false;
        }

        try
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }
        catch
        {
            return false;
        }
    }

    public static bool IsBcryptHash(string? passwordHash)
    {
        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            return false;
        }

        return BcryptPrefixes.Any(prefix =>
            passwordHash.StartsWith(prefix, StringComparison.Ordinal));
    }
}
