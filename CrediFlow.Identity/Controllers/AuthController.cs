using CrediFlow.Identity.DTOs.Auth;
using CrediFlow.Identity.Models;
using CrediFlow.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CrediFlow.Identity.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    /// <summary>
    /// Authenticate user and generate JWT tokens
    /// </summary>
    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var ipAddress = GetClientIpAddress();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.LoginAsync(request, ipAddress, userAgent);

            // Lưu refresh token vào HttpOnly cookie — không bao giờ expose cho JS
            SetRefreshTokenCookie(response.RefreshToken, response.RefreshTokenExpiresAt);
            // Xoá refresh token khỏi response body để không lưu xuống localStorage của FE
            response.RefreshToken = string.Empty;

            _logger.LogInformation("User {Username} logged in successfully from {IpAddress}",
                request.Username, ipAddress);

            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Failed login attempt for {Username}: {Reason}",
                request.Username, ex.Message);
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for {Username}", request.Username);
            return StatusCode(500, new { message = "An error occurred during login" });
        }
    }

    /// <summary>
    /// Refresh access token using refresh token
    /// </summary>
    [AllowAnonymous]
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest? request)
    {
        try
        {
            // Ưu tiên đọc từ HttpOnly cookie, fallback về body (backward compat)
            var token = Request.Cookies["refresh_token"]
                ?? request?.RefreshToken;

            if (string.IsNullOrWhiteSpace(token))
                return Unauthorized(new { message = "Refresh token not provided" });

            var ipAddress = GetClientIpAddress();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.RefreshTokenAsync(token, ipAddress, userAgent);

            // Xoay vòng cookie với refresh token mới
            SetRefreshTokenCookie(response.RefreshToken, response.RefreshTokenExpiresAt);
            response.RefreshToken = string.Empty;

            _logger.LogInformation("Token refreshed successfully for user {UserId}", response.UserId);

            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Failed token refresh: {Reason}", ex.Message);
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token refresh");
            return StatusCode(500, new { message = "An error occurred during token refresh" });
        }
    }

    /// <summary>
    /// Logout and revoke refresh token
    /// </summary>
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Logout()
    {
        try
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new { message = "Invalid user token" });
            }

            // Đọc refresh token từ cookie (HttpOnly)
            var refreshToken = Request.Cookies["refresh_token"];
            await _authService.LogoutAsync(userId, refreshToken);

            // Xoá cookie phía server
            ClearRefreshTokenCookie();

            _logger.LogInformation("User {UserId} logged out successfully", userId);

            return Ok(new { message = "Logged out successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return StatusCode(500, new { message = "An error occurred during logout" });
        }
    }

    /// <summary>
    /// Change user password
    /// </summary>
    [HttpPost("change-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        try
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new { message = "Invalid user token" });
            }

            await _authService.ChangePasswordAsync(userId, request);

            _logger.LogInformation("User {UserId} changed password successfully", userId);

            return Ok(new { message = "Password changed successfully. Please login again with your new password" });
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Unauthorized access during password change: {Reason}", ex.Message);
            return Unauthorized(new { message = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password change");
            return StatusCode(500, new { message = "An error occurred during password change" });
        }
    }

    /// <summary>
    /// Register new user (Admin only)
    /// </summary>
    [Authorize(Roles = "ADMIN,REGIONAL_MANAGER,STORE_MANAGER")]
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
    {
        try
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var createdBy))
            {
                return Unauthorized(new { message = "Invalid user token" });
            }

            // TODO: Add role-based authorization check here when roles are implemented
            // For now, any authenticated user can create new users

            var newUser = await _authService.RegisterUserAsync(request, createdBy);

            _logger.LogInformation("User {CreatedBy} created new user {Username} (ID: {UserId})",
                createdBy, newUser.Username, newUser.UserId);

            return CreatedAtAction(
                nameof(GetCurrentUser),
                new
                {
                    userId = newUser.UserId,
                    username = newUser.Username,
                    fullName = newUser.FullName,
                    email = newUser.Email,
                    phone = newUser.Phone,
                    storeId = newUser.StoreId,
                    isActive = newUser.IsActive,
                    mustChangePassword = newUser.MustChangePassword,
                    createdAt = newUser.CreatedAt,
                    message = "User created successfully. Default password has been set."
                });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("User registration failed: {Reason}", ex.Message);
            return Conflict(new { message = ex.Message });
        }
        catch (KeyNotFoundException ex)
        {
            _logger.LogWarning("User registration failed: {Reason}", ex.Message);
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration");
            return StatusCode(500, new { message = "An error occurred during user registration" });
        }
    }

    /// <summary>
    /// Get current authenticated user info
    /// </summary>
    [HttpGet("me")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetCurrentUser()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var username = User.FindFirst(ClaimTypes.Name)?.Value;
            var fullName = User.FindFirst("full_name")?.Value;
            var email = User.FindFirst("email")?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;
            var storeId = User.FindFirst("store_id")?.Value;
            var storeIds = User.FindAll("assigned_store_id").Select(c => c.Value).ToArray();

            return Ok(new
            {
                userId,
                username,
                fullName,
                email,
                role,
                storeId,
                storeIds
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current user info");
            return StatusCode(500, new { message = "An error occurred" });
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Revoke tất cả sessions của một user (Admin/StoreManager).
    /// Được gọi từ API service khi thay đổi custom roles của user — buộc user đăng nhập lại.
    /// </summary>
    [Authorize(Roles = "ADMIN,REGIONAL_MANAGER,STORE_MANAGER")]
    [HttpPost("revoke-user-sessions/{userId:guid}")]
    public async Task<IActionResult> RevokeUserSessions(Guid userId)
    {
        try
        {
            await _authService.RevokeAllUserSessionsAsync(userId, "Custom roles updated by admin");
            _logger.LogInformation("All sessions revoked for user {UserId}", userId);
            return Ok(new { message = "Sessions revoked. User must log in again." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking sessions for user {UserId}", userId);
            return StatusCode(500, new { message = "An error occurred" });
        }
    }

    /// <summary>
    /// Đặt HttpOnly cookie chứa refresh token.
    /// HttpOnly=true → JS không đọc được; Secure=true (prod) → chỉ qua HTTPS;
    /// SameSite=Strict → chống CSRF; Path=/api/auth → chỉ gửi đến auth endpoints.
    /// </summary>
    private void SetRefreshTokenCookie(string refreshToken, DateTime expiresAt)
    {
        var isProduction = HttpContext.RequestServices
            .GetRequiredService<IWebHostEnvironment>().IsProduction();

        // Dev: Angular chạy http://localhost:4200, identity server chạy https://localhost:7085
        // Chrome Schemeful Same-Site (Chrome 89+) coi khác scheme là cross-site
        // → SameSite=Strict sẽ không gửi cookie qua cross-scheme request
        // → Dùng SameSite=None (cross-site) + Secure=true ở dev
        // Production: cùng domain nên dùng SameSite=Strict để chống CSRF
        Response.Cookies.Append("refresh_token", refreshToken, new CookieOptions
        {
            HttpOnly    = true,
            Secure      = true,                 // Luôn true: SameSite=None yêu cầu Secure; prod HTTPS anyway
            SameSite    = isProduction ? SameSiteMode.Strict : SameSiteMode.None,
            Path        = "/api/auth",          // Cookie chỉ gửi đến auth endpoints
            Expires     = expiresAt,
            IsEssential = true,
        });
    }

    /// <summary>Xóa refresh token cookie (dùng khi logout hoặc revoke).</summary>
    private void ClearRefreshTokenCookie()
    {
        var isProduction = HttpContext.RequestServices
            .GetRequiredService<IWebHostEnvironment>().IsProduction();

        Response.Cookies.Delete("refresh_token", new CookieOptions
        {
            Path     = "/api/auth",
            Secure   = true,
            SameSite = isProduction ? SameSiteMode.Strict : SameSiteMode.None,
        });
    }

    /// <summary>
    /// Lấy IP thực của client, ưu tiên X-Forwarded-For (đã được UseForwardedHeaders xử lý).
    /// Tự động strip prefix ::ffff: của IPv4-mapped IPv6.
    /// </summary>
    private string GetClientIpAddress()
    {
        var ip = HttpContext.Connection.RemoteIpAddress;
        if (ip == null) return "Unknown";
        // IPv4-mapped IPv6 (::ffff:x.x.x.x) → trả về IPv4 thuần
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        return ip.ToString();
    }
}
