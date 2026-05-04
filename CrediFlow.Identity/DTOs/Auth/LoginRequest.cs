using System.ComponentModel.DataAnnotations;

namespace CrediFlow.Identity.DTOs.Auth;

public class LoginRequest
{
    [Required(ErrorMessage = "Tên đăng nhập là bắt buộc")]
    [StringLength(50, ErrorMessage = "Tên đăng nhập không được vượt quá 50 ký tự")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
    [StringLength(100, MinimumLength = 6, ErrorMessage = "Mật khẩu mới phải có ít nhất 6 ký tự")]
    // [RegularExpression(@"^(?=.*[@$!%*?&]).+$",
    //     ErrorMessage = "Mật khẩu phải chứa ít nhất một ký tự đặc biệt (@$!%*?&)")]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Device information for tracking
    /// </summary>
    public string? DeviceInfo { get; set; }
}
