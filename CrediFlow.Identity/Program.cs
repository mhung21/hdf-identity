using System.Net;
using System.Security.Cryptography;
using System.Text;
using CrediFlow.DataContext.Models;
using CrediFlow.Identity.Config;
using CrediFlow.Identity.Services;
using CrediFlow.Identity.Utils;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Serilog;
using Serilog.Sinks.Grafana.Loki;

var builder = WebApplication.CreateBuilder(args);

// =========================================================
// CONFIGURATION
// =========================================================

// Bind JWT settings
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));
var jwtSettings = builder.Configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>()
                  ?? throw new InvalidOperationException("JWT settings not configured");

// =========================================================
// DATABASE
// =========================================================

var connectionString = builder.Configuration.GetConnectionString("CrediFlowConnection")
                       ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found");

builder.Services.AddDbContext<CrediflowContext>(options =>
    options.UseNpgsql(connectionString));

// =========================================================
// AUTHENTICATION & AUTHORIZATION
// =========================================================

// Prepare signing key (ES256 preferred, fallback to HMAC-SHA256)
SecurityKey signingKey;
string algorithm;

// JWKS (JSON Web Key Set) — only populated when ES256 is configured
JsonWebKeySet? jwks = null;

if (!string.IsNullOrEmpty(jwtSettings.EcdsaPublicKey))
{
    // ES256: Load ECDSA public key for token verification
    try
    {
        var ecdsa = EcdsaKeyGenerator.LoadPublicKey(jwtSettings.EcdsaPublicKey);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa);

        // Build JWK from public key parameters for JWKS discovery
        var ecParams = ecdsa.ExportParameters(false);
        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Crv = "P-256",
            Use = "sig",
            Alg = SecurityAlgorithms.EcdsaSha256,
            X   = Base64UrlEncoder.Encode(ecParams.Q.X!),
            Y   = Base64UrlEncoder.Encode(ecParams.Q.Y!)
        };
        // RFC 7638: thumbprint of public key as kid
        jwk.Kid = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
        ecdsaKey.KeyId = jwk.Kid;

        jwks = new JsonWebKeySet();
        jwks.Keys.Add(jwk);

        signingKey = ecdsaKey;
        algorithm = SecurityAlgorithms.EcdsaSha256;
        Console.WriteLine($"✓ JWT verification: ES256 (ECDSA P-256) JWKS enabled, kid={jwk.Kid[..8]}...");
    }
    catch (Exception ex)
    {
        throw new InvalidOperationException("Failed to load ECDSA public key for JWT verification", ex);
    }
}
else if (!string.IsNullOrEmpty(jwtSettings.SecretKey))
{
    // Fallback: HMAC-SHA256 (symmetric — no JWKS support)
    signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey));
    algorithm = SecurityAlgorithms.HmacSha256;
    Console.WriteLine("⚠ JWT verification: HMAC-SHA256 (consider upgrading to ES256)");
}
else
{
    throw new InvalidOperationException(
        "JWT configuration error: Either EcdsaPublicKey or SecretKey must be configured");
}

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = builder.Environment.IsProduction();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = signingKey,
            ValidAlgorithms = new[] { algorithm }, // Only allow configured algorithm
            ClockSkew = TimeSpan.Zero // No tolerance for token expiration
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType().Name == "SecurityTokenExpiredException")
                {
                    context.Response.Headers.Append("X-Token-Expired", "true");
                }
                return Task.CompletedTask;
            },
            OnMessageReceived = context =>
            {
                // Allow token from query string for SignalR/WebSocket scenarios
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs"))
                {
                    context.Token = accessToken;
                }
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// =========================================================
// SERVICES
// =========================================================

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IAuthService, AuthService>();

// Cấu hình ForwardedHeaders để đọc IP thực từ nginx (X-Forwarded-For)
// Tin tưởng tất cả các Private network thường dùng trong Docker/private proxy
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Clear mặc định (chỉ trust loopback) và trust các Docker/private network
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Parse("10.0.0.0"), 8));
    options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Parse("172.16.0.0"), 12));  // Docker bridge 172.16–172.31
    options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Parse("192.168.0.0"), 16));
    options.KnownProxies.Add(IPAddress.Loopback);
    options.KnownProxies.Add(IPAddress.IPv6Loopback);
});
// =========================================================
// CORS
// =========================================================

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins(
                "http://localhost:4200",  // Angular dev server
                "http://localhost:3000",  // Alternative port
                "https://localhost:4200",
                "https://localhost:3000",
                "https://localhost:7085",
                "https://quanly.hdfinanceco.vn",  // Production domain
                "https://quanly-dev.hdfinanceco.vn", // Test domain
                "http://103.176.179.103:8080",    // Test frontend
                "http://103.176.179.103:8883",    // Test API
                "http://103.176.179.103:8884"     // Test Identity
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

// =========================================================
// API DOCUMENTATION
// =========================================================

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "CrediFlow Identity API",
        Version = "v1",
        Description = "Authentication and authorization service for CrediFlow loan management system"
    });

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token in the format: Bearer {token}"
    });

    //c.AddSecurityRequirement(new OpenApiSecurityRequirement
    //{
    //    {
    //        new OpenApiSecurityScheme
    //        {
    //            Reference = new OpenApiReference
    //            {
    //                Type = ReferenceType.SecurityScheme,
    //                Id = "Bearer"
    //            }
    //        },
    //        Array.Empty<string>()
    //    }
    //});
});

// =========================================================
// HEALTHCHECK
// =========================================================

//builder.Services.AddHealthChecks()
//    .AddNpgSql(connectionString, name: "database");

// =========================================================
// SERILOG LOGGING
// =========================================================
var lokiUrl = builder.Configuration["Loki:Url"] ?? "http://hdf-loki:3100";

builder.Host.UseSerilog((context, config) =>
{
    config
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("service_name", "hdf-identity")
        .Enrich.WithProperty("environment", context.HostingEnvironment.EnvironmentName)
        .WriteTo.Console()
        .WriteTo.GrafanaLoki(
            uri: lokiUrl,
            labels: new List<LokiLabel>
            {
                new() { Key = "service_name", Value = "hdf-identity" },
                new() { Key = "environment", Value = context.HostingEnvironment.EnvironmentName }
            },
            propertiesAsLabels: new[] { "level" }
        );
});

// =========================================================
// APP BUILD
// =========================================================

var app = builder.Build();

// =========================================================
// MIDDLEWARE PIPELINE
// =========================================================

// Development tools
if (!app.Environment.IsProduction())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "CrediFlow Identity API v1");
        c.RoutePrefix = string.Empty; // Serve Swagger at root
    });
}

// Serilog HTTP request logging (auto-log method, path, status code, duration)
app.UseSerilogRequestLogging();

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

// Log toàn bộ hệ thống (những chỗ không có try catch thì lỗi sẽ bắn vào đây) => Như vậy có thể bỏ hết try catch trên các controller đi
//https://stackoverflow.com/questions/38630076/asp-net-core-web-api-exception-handling

app.UseExceptionHandler(a => a.Run(async context =>
{
    var exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();
    if (exceptionHandlerPathFeature?.Error == null)
    {
        await context.Response.WriteAsJsonAsync(new { error = "An unknown error occurred" });
        return;
    }
    
    var ex = exceptionHandlerPathFeature.Error;

    Log.Error(ex, "Unhandled exception at {Path}", exceptionHandlerPathFeature.Path);

    // var objLog = new
    // {
    //     ServiceName = "LASI api - " + builder.Configuration.GetValue("Scope:Environment", ""),
    //     Source = ex.Source,
    //     Path = exceptionHandlerPathFeature.Path,
    //     Url = $"{context.Request.Scheme}://{context.Request.Host.Value}{context.Request.Path}",
    //     Message = ex.Message,
    //     InnerException = ex.InnerException?.ToString(),
    //     StackTrace = ex.StackTrace,
    //     Data = JsonConvert.SerializeObject(ex.Data)
    // };
    
    // //TODO
    // //Lib.PushToLog(objLog);

    // var result = CommonLib.ConvertObjectToJson(ResultAPI.Error(ex.Message));
    // context.Response.StatusCode = 200;  // (int)HttpStatusCode.InternalServerError;
    // context.Response.ContentType = "application/json";
    // await context.Response.WriteAsync(result);
}));


// ForwardedHeaders phải được xử lý ĐẦU TIÊN trước mọi middleware khác
// để RemoteIpAddress được cập nhật đúng từ X-Forwarded-For của nginx
app.UseForwardedHeaders();

// CORS must be before Authentication
app.UseCors("AllowFrontend");

// HTTPS redirection: Disabled vì Nginx xử lý SSL/TLS termination (reverse proxy).
// App chỉ nhận HTTP từ nginx trên port 8882, nên middleware này sẽ gây redirect loop:
//   Browser → HTTPS → Nginx → HTTP/8882 → UseHttpsRedirection → 301 HTTPS → loop
// Tương tự cách xử lý trong CrediFlow.API/Program.cs.
// if (!app.Environment.IsDevelopment())
// {
//     app.UseHttpsRedirection();
// }

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

// Health check endpoint
// app.MapHealthChecks("/health");

// API Controllers
app.MapControllers();

// =========================================================
// JWKS / OIDC DISCOVERY ENDPOINTS
// =========================================================

// Only exposed when ES256 (ECDSA) is configured — HMAC has no public key to publish
if (jwks != null)
{
    var capturedJwks = jwks;

    // RFC 7517: JSON Web Key Set — lets other services fetch the public key dynamically
    app.MapGet("/.well-known/jwks.json", () =>
    {
        var keys = capturedJwks.Keys.Select(k => new
        {
            kty = k.Kty,
            crv = k.Crv,
            use = k.Use,
            alg = k.Alg,
            kid = k.Kid,
            x   = k.X,
            y   = k.Y
        });
        return Results.Json(new { keys });
    }).AllowAnonymous();

    // OpenID Connect discovery document — other services point Authority here
    app.MapGet("/.well-known/openid-configuration", (HttpContext ctx) =>
    {
        var issuer = jwtSettings.Issuer;
        // Use the request's own base URL for jwks_uri so internal Docker calls work
        var baseUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
        return Results.Json(new
        {
            issuer,
            jwks_uri                              = $"{baseUrl}/.well-known/jwks.json",
            token_endpoint                        = $"{baseUrl}/api/auth/login",
            id_token_signing_alg_values_supported = new[] { "ES256" },
            subject_types_supported               = new[] { "public" },
            response_types_supported              = new[] { "token" }
        });
    }).AllowAnonymous();
}

// =========================================================
// RUN APPLICATION
// =========================================================

app.Logger.LogInformation("CrediFlow Identity Service starting on {Environment}", app.Environment.EnvironmentName);
app.Logger.LogInformation("JWT Issuer: {Issuer}, Audience: {Audience}", jwtSettings.Issuer, jwtSettings.Audience);

app.Run();
