using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using AuthApi.Data;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using Swashbuckle.AspNetCore.SwaggerGen;
using Microsoft.OpenApi.Models;

namespace AuthApi;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Setup logging
        builder.Logging.ClearProviders(); // Clears the default logging providers
        builder.Logging.AddConsole(); // Add console logging
        builder.Logging.AddDebug(); // Add debug logging (optional)

        var configuration = builder.Configuration;

        // Add services to the container.
        builder.Services.AddDbContext<AppDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));

        // Add Identity services
        builder.Services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

        // Load RSA keys from User Secrets
        var privateKeyBase64 = configuration["Jwt:PrivateKey"];
        var publicKeyBase64 = configuration["Jwt:PublicKey"];

        if (string.IsNullOrEmpty(privateKeyBase64) || string.IsNullOrEmpty(publicKeyBase64))
            throw new InvalidOperationException("RSA keys are missing from User Secrets. Set them using 'dotnet user-secrets set'.");

        // Convert Base64 keys back to RSA
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyBase64);

        // Add OpenIddict services
        builder.Services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<AppDbContext>();
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetTokenEndpointUris("/connect/token");

                options.AllowPasswordFlow()
                    .AllowRefreshTokenFlow();

                // Use RSA keys for signing JWTs
                options.AddSigningKey(new RsaSecurityKey(rsa));

                // Enable JWT tokens
                options.UseReferenceAccessTokens();
            })
            .AddValidation();

        // Add JWT authentication
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = "https://localhost:5001"; // Replace with your auth server's URL
                options.Audience = "api"; // Set to your audience (if needed)
                options.RequireHttpsMetadata = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new RsaSecurityKey(rsa) // Use the same RSA key for validation
                };
            });

        // Add Swagger services
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Auth API",
                Version = "v1",
                Description = "An API for user authentication and token management using OpenIddict"
            });

            // Define the security scheme for Bearer authentication
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header,
                Description = "Please enter a valid JWT token",
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey
            });

            // Apply the security requirement to all operations
            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
            });
        });

        builder.Services.AddControllers();

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth API v1");
                c.RoutePrefix = string.Empty; // This will make Swagger UI accessible at the root URL
            });
        }

        // Use CORS middleware if needed (ensure CORS is set up)
        app.UseCors();

        // Authentication and Authorization middleware
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}
