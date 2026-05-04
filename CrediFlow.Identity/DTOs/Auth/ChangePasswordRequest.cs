using System.ComponentModel.DataAnnotations;

namespace CrediFlow.Identity.DTOs.Auth;

public class ChangePasswordRequest
{
    [Required(ErrorMessage = "Vui lòng nhập mật khẩu hiện tại")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Vui lòng nhập mật khẩu mới")]
    [StringLength(100, MinimumLength = 6, ErrorMessage = "Mật khẩu mới phải có ít nhất 6 ký tự")]
    // [RegularExpression(@"^(?=.*[@$!%*?&]).+$",
    //     ErrorMessage = "Mật khẩu phải chứa ít nhất một ký tự đặc biệt (@$!%*?&)")]
    public string NewPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Vui lòng xác nhận mật khẩu mới")]
    [Compare("NewPassword", ErrorMessage = "Mật khẩu mới và xác nhận mật khẩu không khớp")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
