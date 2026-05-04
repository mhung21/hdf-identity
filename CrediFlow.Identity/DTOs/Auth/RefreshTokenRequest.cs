using System.ComponentModel.DataAnnotations;

namespace CrediFlow.Identity.DTOs.Auth;

public class RefreshTokenRequest
{
    // Optional: nếu không cung cấp, server đọc từ HttpOnly cookie "refresh_token"
    public string? RefreshToken { get; set; }
}
