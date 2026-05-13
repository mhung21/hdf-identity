using CrediFlow.DataContext.Models;
using Microsoft.AspNetCore.Http;
using System.Net;

namespace CrediFlow.Identity.Services;

public interface IPasswordAuditService
{
    Task LogPasswordChangedAsync(Guid userId, Guid? storeId);
}

public class PasswordAuditService : IPasswordAuditService
{
    private readonly CrediflowContext _context;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<PasswordAuditService> _logger;

    public PasswordAuditService(
        CrediflowContext context,
        IHttpContextAccessor httpContextAccessor,
        ILogger<PasswordAuditService> logger)
    {
        _context = context;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task LogPasswordChangedAsync(Guid userId, Guid? storeId)
    {
        try
        {
            var ip = ResolveClientIp();

            _context.DataAccessLogs.Add(new DataAccessLog
            {
                AccessLogId = Guid.CreateVersion7(),
                UserId = userId,
                StoreId = storeId,
                ResourceType = "ACCOUNT_SECURITY",
                ResourceId = userId,
                Action = "PASSWORD_CHANGE",
                AccessedAt = DateTime.Now,
                IpAddress = ip,
                ResponseStatus = 200,
                Note = "User changed password and all active sessions were revoked"
            });

            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[PasswordAuditService] Could not write PASSWORD_CHANGE audit log for user {UserId}", userId);
        }
    }

    private IPAddress? ResolveClientIp()
    {
        var ip = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress;
        if (ip?.IsIPv4MappedToIPv6 == true)
        {
            ip = ip.MapToIPv4();
        }

        return ip;
    }
}
