using System.ComponentModel.DataAnnotations;
using static CrediFlow.Common.Utils.Consts;


namespace CrediFlow.Identity.DTOs.Auth;

public class RegisterUserRequest
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, underscore, dot, and hyphen")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Full name is required")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "Full name must be between 2 and 100 characters")]
    public string FullName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
    public string Password { get; set; } = string.Empty;

    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(150)]
    public string? Email { get; set; }

    [Phone(ErrorMessage = "Invalid phone format")]
    [StringLength(20)]
    public string? Phone { get; set; }

    [Required(ErrorMessage = "Role is required")]
    public UserRoleCode RoleCode { get; set; } = UserRoleCode.STAFF;

    public Guid? StoreId { get; set; }

    public List<Guid>? StoreIds { get; set; }

    public bool IsActive { get; set; } = true;

    public bool MustChangePassword { get; set; } = true;
}
