using CrediFlow.DataContext.Models;
using CrediFlow.Identity.Config;
using CrediFlow.Identity.DTOs.Auth;
using CrediFlow.Identity.Utils;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static CrediFlow.Common.Utils.Consts;

namespace CrediFlow.Identity.Services;

public interface IAuthService
{
    Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken, string ipAddress, string userAgent);
    Task LogoutAsync(Guid userId, string? refreshToken);
    Task<bool> ChangePasswordAsync(Guid userId, ChangePasswordRequest request);
    Task RevokeAllUserSessionsAsync(Guid userId, string reason);
    Task<AppUser> RegisterUserAsync(RegisterUserRequest request, Guid createdBy);
}

public class AuthService : IAuthService
{
    private readonly CrediflowContext _context;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<AuthService> _logger;
    private readonly ECDsa? _ecdsaPrivateKey;
    private readonly string? _kid; // RFC 7638 JWK thumbprint, matches JWKS endpoint

    public AuthService(
        CrediflowContext context,
        IOptions<JwtSettings> jwtSettings,
        ILogger<AuthService> logger)
    {
        _context = context;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;

        // Load ECDSA private key for ES256 signing if configured
        if (!string.IsNullOrEmpty(_jwtSettings.EcdsaPrivateKey))
        {
            try
            {
                _ecdsaPrivateKey = EcdsaKeyGenerator.LoadPrivateKey(_jwtSettings.EcdsaPrivateKey);
                _logger.LogInformation("ES256 (ECDSA P-256) signing enabled for JWT tokens");

                // Compute kid from the public key parameters (RFC 7638 thumbprint)
                // Private & public key share the same Q point → same thumbprint as JWKS endpoint
                var ecParams = _ecdsaPrivateKey.ExportParameters(false);
                var tempJwk = new JsonWebKey
                {
                    Kty = "EC",
                    Crv = "P-256",
                    X = Base64UrlEncoder.Encode(ecParams.Q.X!),
                    Y = Base64UrlEncoder.Encode(ecParams.Q.Y!)
                };
                _kid = Base64UrlEncoder.Encode(tempJwk.ComputeJwkThumbprint());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load ECDSA private key. Falling back to HMAC-SHA256");
            }
        }
        else if (string.IsNullOrEmpty(_jwtSettings.SecretKey))
        {
            throw new InvalidOperationException(
                "JWT configuration error: Either EcdsaPrivateKey or SecretKey must be configured");
        }
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent)
    {
        var normalizedUsername = request.Username.Trim();

        // Find user by username (WITH tracking because we need to update it)
        // But NO Include for performance
        var user = await _context.AppUsers
            .FirstOrDefaultAsync(u => u.Username.ToLower() == normalizedUsername.ToLower());

        // Log login attempt
        var loginHistory = new UserLoginHistory
        {
            UserId = user?.UserId,
            Username = normalizedUsername,
            LoginAt = DateTime.Now,
            IpAddress = IPAddress.TryParse(ipAddress, out var loginIp) ? loginIp : null,
            UserAgent = userAgent,
            IsSuccess = false
        };

        try
        {
            // Check if user exists
            if (user == null)
            {
                loginHistory.FailureReason = "User not found";
                await _context.UserLoginHistories.AddAsync(loginHistory);
                await _context.SaveChangesAsync();
                throw new UnauthorizedAccessException("Invalid username or password");
            }

            // Check if user is active
            if (!user.IsActive)
            {
                loginHistory.FailureReason = "Account is inactive";
                await _context.UserLoginHistories.AddAsync(loginHistory);
                await _context.SaveChangesAsync();
                throw new UnauthorizedAccessException("Your account has been deactivated");
            }

            // Check if account is locked
            if (user.LockedUntil.HasValue && user.LockedUntil.Value > DateTime.Now)
            {
                var lockTimeRemaining = (user.LockedUntil.Value - DateTime.Now).TotalMinutes;
                loginHistory.FailureReason = $"Account is locked for {Math.Ceiling(lockTimeRemaining)} more minutes";
                await _context.UserLoginHistories.AddAsync(loginHistory);
                await _context.SaveChangesAsync();
                throw new UnauthorizedAccessException($"Account is locked. Try again in {Math.Ceiling(lockTimeRemaining)} minutes");
            }

            if (!PasswordHashing.IsBcryptHash(user.PasswordHash))
            {
                _logger.LogWarning(
                    "User {UserId} has unsupported password hash format. Only BCrypt is supported for new passwords.",
                    user.UserId);
            }

            // Verify password bằng chuẩn BCrypt duy nhất của hệ thống
            if (!PasswordHashing.VerifyPassword(request.Password, user.PasswordHash))
            {
                // Increment failed login attempts
                user.FailedLoginAttempts++;

                // Lock account if max attempts exceeded
                if (user.FailedLoginAttempts >= _jwtSettings.MaxFailedLoginAttempts)
                {
                    user.LockedUntil = DateTime.Now.AddMinutes(_jwtSettings.LockoutDurationMinutes);
                    loginHistory.FailureReason = "Too many failed attempts - account locked";
                }
                else
                {
                    loginHistory.FailureReason = "Invalid password";
                }

                await _context.UserLoginHistories.AddAsync(loginHistory);
                await _context.SaveChangesAsync();

                throw new UnauthorizedAccessException("Invalid username or password");
            }

            // Reset failed login attempts on successful login
            user.FailedLoginAttempts = 0;
            user.LockedUntil = null;
            user.LastLoginAt = DateTime.Now;

            // Get user permissions first (needed for JWT claims)
            var permissions = await GetUserPermissionsAsync(user.UserId);

            // Generate tokens
            var accessToken = await GenerateAccessToken(user, permissions);
            var refreshToken = GenerateRefreshToken();
            var refreshTokenHash = HashRefreshToken(refreshToken);

            // Store refresh token in database
            var session = new UserSession
            {
                SessionId = Guid.CreateVersion7(),
                UserId = user.UserId,
                RefreshTokenHash = refreshTokenHash,
                IpAddress = IPAddress.TryParse(ipAddress, out var sessionIp) ? sessionIp : null,
                UserAgent = userAgent,
                DeviceInfo = request.DeviceInfo,
                ExpiresAt = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpirationDays),
                CreatedAt = DateTime.Now
            };

            await _context.UserSessions.AddAsync(session);

            // Mark login as successful
            loginHistory.IsSuccess = true;
            loginHistory.FailureReason = null;
            loginHistory.UserId = user.UserId;
            await _context.UserLoginHistories.AddAsync(loginHistory);

            await _context.SaveChangesAsync();

            // Parse role code
            var roleCode = ParseRoleCode(user.RoleCode);

            // Get store name if user has store (single query, no Include)
            string? storeName = null;
            if (user.StoreId.HasValue)
            {
                storeName = await _context.Stores
                    .AsNoTracking()
                    .Where(s => s.StoreId == user.StoreId.Value)
                    .Select(s => s.StoreName)
                    .FirstOrDefaultAsync();
            }

            // Build response
            return new AuthResponse
            {
                UserId = user.UserId,
                Username = user.Username,
                FullName = user.FullName,
                Email = user.Email ?? string.Empty,
                RoleCode = roleCode,
                StoreId = user.StoreId,
                StoreName = storeName,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpiresAt = DateTime.Now.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                RefreshTokenExpiresAt = session.ExpiresAt,
                Permissions = permissions,
                MustChangePassword = user.MustChangePassword
            };
        }
        catch
        {
            // Ensure login failure is logged even if exception occurs
            if (!loginHistory.IsSuccess && !_context.UserLoginHistories.Local.Contains(loginHistory))
            {
                await _context.UserLoginHistories.AddAsync(loginHistory);
                await _context.SaveChangesAsync();
            }
            throw;
        }
    }

    public async Task<AuthResponse> RefreshTokenAsync(string refreshToken, string ipAddress, string userAgent)
    {
        var refreshTokenHash = HashRefreshToken(refreshToken);

        // Find valid session with projection (only get needed fields)
        var sessionData = await _context.UserSessions
            .AsNoTracking()
            .Where(s =>
                s.RefreshTokenHash == refreshTokenHash &&
                s.RevokedAt == null &&
                s.ExpiresAt > DateTime.Now)
            .Select(s => new { s.SessionId, s.UserId, s.DeviceInfo })
            .FirstOrDefaultAsync();

        if (sessionData == null)
        {
            throw new UnauthorizedAccessException("Invalid or expired refresh token");
        }

        // Get user separately
        var user = await _context.AppUsers
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.UserId == sessionData.UserId);

        if (user == null)
        {
            throw new UnauthorizedAccessException("User not found");
        }

        // Check if user is still active
        if (!user.IsActive)
        {
            throw new UnauthorizedAccessException("Account is inactive");
        }

        // Get user permissions first (needed for JWT claims)
        var permissions = await GetUserPermissionsAsync(user.UserId);

        // Generate new tokens
        var newAccessToken = await GenerateAccessToken(user, permissions);
        var newRefreshToken = GenerateRefreshToken();
        var newRefreshTokenHash = HashRefreshToken(newRefreshToken);

        // Revoke old session using ExecuteUpdate (more performant)
        await _context.UserSessions
            .Where(s => s.SessionId == sessionData.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.RevokedAt, DateTime.Now));

        // Create new session
        var newSession = new UserSession
        {
            SessionId = Guid.CreateVersion7(),
            UserId = user.UserId,
            RefreshTokenHash = newRefreshTokenHash,
            IpAddress = IPAddress.TryParse(ipAddress, out var parsedIp) ? parsedIp : null,
            UserAgent = userAgent,
            DeviceInfo = sessionData.DeviceInfo,
            ExpiresAt = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpirationDays),
            CreatedAt = DateTime.Now
        };

        await _context.UserSessions.AddAsync(newSession);
        await _context.SaveChangesAsync();

        var roleCode = ParseRoleCode(user.RoleCode);

        // Get store name if needed
        string? storeName = null;
        if (user.StoreId.HasValue)
        {
            storeName = await _context.Stores
                .AsNoTracking()
                .Where(s => s.StoreId == user.StoreId.Value)
                .Select(s => s.StoreName)
                .FirstOrDefaultAsync();
        }

        return new AuthResponse
        {
            UserId = user.UserId,
            Username = user.Username,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            RoleCode = roleCode,
            StoreId = user.StoreId,
            StoreName = storeName,
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            AccessTokenExpiresAt = DateTime.Now.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            RefreshTokenExpiresAt = newSession.ExpiresAt,
            Permissions = permissions,
            MustChangePassword = user.MustChangePassword
        };
    }

    public async Task LogoutAsync(Guid userId, string? refreshToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            // Không có token cụ thể → revoke tất cả session của user để an toàn
            await RevokeAllUserSessionsAsync(userId, "Logout without token");
            return;
        }

        var refreshTokenHash = HashRefreshToken(refreshToken);

        var session = await _context.UserSessions
            .Where(s =>
                s.UserId == userId &&
                s.RefreshTokenHash == refreshTokenHash &&
                s.RevokedAt == null)
            .FirstOrDefaultAsync();

        if (session != null)
        {
            session.RevokedAt = DateTime.Now;
            await _context.SaveChangesAsync();
        }
    }

    public async Task<bool> ChangePasswordAsync(Guid userId, ChangePasswordRequest request)
    {
        var user = await _context.AppUsers.FindAsync(userId);
        if (user == null)
        {
            throw new KeyNotFoundException("User not found");
        }

        if (!PasswordHashing.IsBcryptHash(user.PasswordHash))
        {
            _logger.LogWarning(
                "User {UserId} has unsupported password hash format during password change. Only BCrypt is supported.",
                userId);
        }

        // Verify current password
        if (!PasswordHashing.VerifyPassword(request.CurrentPassword, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Current password is incorrect");
        }

        // Hash new password
        user.PasswordHash = PasswordHashing.HashPassword(request.NewPassword);
        user.PasswordChangedAt = DateTime.Now;
        user.MustChangePassword = false;

        await _context.SaveChangesAsync();

        // Revoke all existing sessions (force re-login with new password)
        await RevokeAllUserSessionsAsync(userId, "Password changed");

        return true;
    }

    public async Task RevokeAllUserSessionsAsync(Guid userId, string reason)
    {
        // Optimized: Use ExecuteUpdate instead of loading entities into memory
        await _context.UserSessions
            .Where(s => s.UserId == userId && s.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.RevokedAt, DateTime.Now));
    }

    public async Task<AppUser> RegisterUserAsync(RegisterUserRequest request, Guid createdBy)
    {
        // Get creator user with role
        var creator = await _context.AppUsers.FindAsync(createdBy);
        if (creator == null)
        {
            throw new UnauthorizedAccessException("Invalid creator user");
        }

        var creatorRole = ParseRoleCode(creator.RoleCode);
        var requestedRole = request.RoleCode;
        var requestedStoreIds = request.StoreIds?
            .Where(id => id != Guid.Empty)
            .Distinct()
            .ToList() ?? [];

        // AUTHORIZATION CHECKS based on role
        // Rule 1: ADMIN can create any user for any store
        // Rule 2: STORE_MANAGER can only create STAFF for their own store
        // Rule 3: STAFF cannot create users at all

        if (creatorRole == UserRoleCode.STAFF)
        {
            throw new UnauthorizedAccessException("You do not have permission to create users");
        }

        if (creatorRole == UserRoleCode.REGIONAL_MANAGER)
        {
            if (requestedRole != UserRoleCode.STAFF)
            {
                throw new UnauthorizedAccessException("Regional managers can only create STAFF users");
            }

            if (!request.StoreId.HasValue)
            {
                throw new InvalidOperationException("Store ID is required when regional managers create users");
            }

            var canManageStore = await _context.UserStoreAssignments
                .AnyAsync(a => a.UserId == createdBy && a.StoreId == request.StoreId.Value);

            if (!canManageStore)
            {
                throw new UnauthorizedAccessException("You can only create users for stores assigned to your region");
            }
        }

        if (creatorRole == UserRoleCode.STORE_MANAGER)
        {
            // STORE_MANAGER restrictions
            if (request.RoleCode != UserRoleCode.STAFF)
            {
                throw new UnauthorizedAccessException("Store managers can only create STAFF users");
            }

            if (request.StoreId != creator.StoreId)
            {
                throw new UnauthorizedAccessException("You can only create users for your own store");
            }

            // Must specify store
            if (!request.StoreId.HasValue)
            {
                throw new InvalidOperationException("Store ID is required when creating users");
            }
        }

        if (creatorRole == UserRoleCode.ADMIN)
        {
            // ADMIN can create anyone but with validation
            // ADMIN and REGIONAL_MANAGER must NOT have storeId (chi nhánh gắn qua bảng user_store_assignments)
            // STORE_MANAGER and STAFF must have storeId
            if ((requestedRole == UserRoleCode.ADMIN || requestedRole == UserRoleCode.REGIONAL_MANAGER)
                && request.StoreId.HasValue)
            {
                throw new InvalidOperationException($"{requestedRole} users cannot be assigned to a single store");
            }

            if (requestedRole == UserRoleCode.REGIONAL_MANAGER && requestedStoreIds.Count == 0)
            {
                throw new InvalidOperationException("StoreIds are required when creating REGIONAL_MANAGER users");
            }

            if (requestedRole != UserRoleCode.ADMIN
                && requestedRole != UserRoleCode.REGIONAL_MANAGER
                && !request.StoreId.HasValue)
            {
                throw new InvalidOperationException($"{requestedRole} users must be assigned to a store");
            }
        }

        // Check if username already exists
        var existingUser = await _context.AppUsers
            .AsNoTracking()
            .AnyAsync(u => u.Username == request.Username);

        if (existingUser)
        {
            throw new InvalidOperationException($"Username '{request.Username}' is already taken");
        }

        // Check if email already exists (if provided)
        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            var existingEmail = await _context.AppUsers
                .AsNoTracking()
                .AnyAsync(u => u.Email == request.Email);

            if (existingEmail)
            {
                throw new InvalidOperationException($"Email '{request.Email}' is already registered");
            }
        }

        // Validate store exists (if provided)
        if (request.StoreId.HasValue)
        {
            var storeExists = await _context.Stores
                .AnyAsync(s => s.StoreId == request.StoreId.Value);

            if (!storeExists)
            {
                throw new KeyNotFoundException($"Store with ID '{request.StoreId}' not found");
            }
        }

        if (requestedStoreIds.Count > 0)
        {
            var existingStoreCount = await _context.Stores
                .CountAsync(s => requestedStoreIds.Contains(s.StoreId));

            if (existingStoreCount != requestedStoreIds.Count)
            {
                throw new KeyNotFoundException("One or more store IDs were not found");
            }
        }

        await using var tx = await _context.Database.BeginTransactionAsync();

        // Create new user
        var newUser = new AppUser
        {
            UserId = Guid.CreateVersion7(),
            Username = request.Username,
            PasswordHash = PasswordHashing.HashPassword(request.Password),
            FullName = request.FullName,
            Email = request.Email,
            Phone = request.Phone,
            RoleCode = requestedRole.ToString(),
            StoreId = requestedRole is UserRoleCode.ADMIN or UserRoleCode.REGIONAL_MANAGER
                ? null
                : request.StoreId,
            IsActive = request.IsActive,
            MustChangePassword = request.MustChangePassword,
            FailedLoginAttempts = 0,
            PasswordChangedAt = DateTime.Now,
            CreatedAt = DateTime.Now,
            UpdatedAt = DateTime.Now
        };

        await _context.AppUsers.AddAsync(newUser);
        await _context.SaveChangesAsync();

        if (requestedRole == UserRoleCode.REGIONAL_MANAGER)
        {
            var assignments = requestedStoreIds.Select(storeId => new UserStoreAssignment
            {
                AssignmentId = Guid.CreateVersion7(),
                UserId = newUser.UserId,
                StoreId = storeId,
                AssignedAt = DateTime.Now,
            }).ToList();

            await _context.UserStoreAssignments.AddRangeAsync(assignments);
            await _context.SaveChangesAsync();
        }

        await tx.CommitAsync();

        _logger.LogInformation(
            "User {Username} (ID: {UserId}, Role: {Role}) created by {CreatorRole} {CreatedBy}",
            newUser.Username, newUser.UserId, newUser.RoleCode, creatorRole, createdBy);

        return newUser;
    }

    #region Private Helper Methods

    private async Task<string> GenerateAccessToken(AppUser user, IEnumerable<string> permissions)
    {
        var roleCode = user.RoleCode.ToUpper();

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, roleCode),
            new("full_name", user.FullName),
            new("email", user.Email ?? string.Empty),
            new("role_code", roleCode),
            new("is_active", user.IsActive.ToString().ToLower()),
            new("is_admin", (roleCode == "ADMIN").ToString().ToLower()),
            new("is_store_manager", (roleCode == "STORE_MANAGER").ToString().ToLower()),
            new("is_regional_manager", (roleCode == "REGIONAL_MANAGER").ToString().ToLower()),
        };

        if (user.StoreId.HasValue)
        {
            claims.Add(new Claim("store_id", user.StoreId.Value.ToString()));
        }

        // Nếu là REGIONAL_MANAGER, thêm claim assigned_store_id cho từng chi nhánh phụ trách
        if (roleCode == "REGIONAL_MANAGER")
        {
            var assignedStoreIds = await _context.UserStoreAssignments
                .AsNoTracking()
                .Where(a => a.UserId == user.UserId)
                .Select(a => a.StoreId)
                .ToListAsync();

            foreach (var storeId in assignedStoreIds)
                claims.Add(new Claim("assigned_store_id", storeId.ToString()));
        }
        if (permissions != null)
        {
            // Ghi nhiều claim riêng lẻ thay vì 1 JSON array — phù hợp với UserInfoService.FindAll("permission")
            foreach (var perm in permissions)
                claims.Add(new Claim("permission", perm));
        }

        // Choose signing algorithm: ES256 (ECDSA) preferred, fallback to HS256 (HMAC)
        SigningCredentials credentials;
        if (_ecdsaPrivateKey != null)
        {
            // ES256: ECDSA with P-256 curve and SHA-256
            // KeyId = kid that matches the JWKS endpoint — receivers can validate via key discovery
            var ecdsaKey = new ECDsaSecurityKey(_ecdsaPrivateKey) { KeyId = _kid };
            credentials = new SigningCredentials(ecdsaKey, SecurityAlgorithms.EcdsaSha256);
        }
        else
        {
            // Fallback to HMAC-SHA256 (symmetric)
            var hmacKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            credentials = new SigningCredentials(hmacKey, SecurityAlgorithms.HmacSha256);
        }

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    private static string HashRefreshToken(string refreshToken)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
        return Convert.ToBase64String(hashBytes);
    }

    private async Task<List<string>> GetUserPermissionsAsync(Guid userId)
    {
        // Lấy RoleCode của user
        var roleCode = await _context.AppUsers.AsNoTracking()
            .Where(u => u.UserId == userId)
            .Select(u => u.RoleCode)
            .FirstOrDefaultAsync();

        if (roleCode == null) return [];

        // 1. Quyền từ vai trò gốc (role_permissions)
        var rolePerms = await _context.RolePermissions
            .AsNoTracking()
            .Where(rp => rp.RoleCode == roleCode)
            .Join(
                _context.Permissions.Where(p => p.IsActive),
                rp => rp.PermissionId,
                p => p.PermissionId,
                (_, p) => p.PermissionCode
            )
            .ToListAsync();

        // 2. Quyền từ vai trò bổ sung (user_custom_roles → custom_role_permissions)
        var customRolePerms = await (
            from ucr in _context.UserCustomRoles
            where ucr.UserId == userId
            join cr in _context.CustomRoles on ucr.CustomRoleId equals cr.CustomRoleId
            where cr.IsActive
            join crp in _context.CustomRolePermissions on cr.CustomRoleId equals crp.CustomRoleId
            join p in _context.Permissions on crp.PermissionId equals p.PermissionId
            where p.IsActive
            select p.PermissionCode
        ).Distinct().ToListAsync();

        // 3. Ghi đè theo từng user (user_permissions: có thể cấp thêm hoặc thu hồi)
        var userOverrides = await _context.UserPermissions
            .AsNoTracking()
            .Where(up => up.UserId == userId)
            .Join(
                _context.Permissions.Where(p => p.IsActive),
                up => up.PermissionId,
                p => p.PermissionId,
                (up, p) => new { Code = p.PermissionCode, up.IsGranted }
            )
            .ToListAsync();

        // Merge: gốc + vai trò bổ sung, sau đó áp dụng ghi đè per-user
        var merged = new HashSet<string>(rolePerms);
        merged.UnionWith(customRolePerms);
        foreach (var ovr in userOverrides)
        {
            if (ovr.IsGranted) merged.Add(ovr.Code);
            else merged.Remove(ovr.Code);
        }

        return [.. merged];
    }

    private static UserRoleCode ParseRoleCode(string roleCode)
    {
        if (Enum.TryParse<UserRoleCode>(roleCode, true, out var result))
        {
            return result;
        }

        // Default to STAFF if invalid
        return UserRoleCode.STAFF;
    }

    #endregion
}
