using Ardalis.GuardClauses;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthApi.Controllers;

[ApiController]
[Route("[controller]")]
public class ConnectController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly ILogger<ConnectController> _logger;

    // Primary constructor
    public ConnectController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        ILogger<ConnectController> logger
    )
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    /// <summary>
    /// Register a new user.
    /// </summary>
    /// <param name="registerDto">User registration data</param>
    /// <returns>Confirmation of successful registration</returns>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        _logger.LogInformation("User registration attempted for: {Username}", registerDto.Username);

        var user = new IdentityUser { UserName = registerDto.Username, Email = registerDto.Email };

        var result = await _userManager.CreateAsync(user, registerDto.Password);
        if (!result.Succeeded)
        {
            _logger.LogWarning("User registration failed for: {Username}", registerDto.Username);
            return BadRequest(result.Errors);
        }

        _logger.LogInformation("User registered successfully: {Username}", registerDto.Username);
        return Ok("User registered successfully.");
    }

    public class RegisterDto
    {
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
    }

    [HttpPost("token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            return BadRequest("Invalid OpenID Connect request.");
        }

        if (request.IsPasswordGrantType())
        {
            _logger.LogInformation("Token exchange requested for user: {Username}", request.Username);

            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                _logger.LogWarning("Token exchange failed - Invalid credentials for user: {Username}", request.Username);
                return Unauthorized("Invalid username or password.");
            }

            _logger.LogInformation("User {Username} authenticated. Generating token.", request.Username);

            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Add required claims
            identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
            identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName!);
            identity.AddClaim(OpenIddictConstants.Claims.Audience, "AuthApi");

            // Set scopes (ensure they are valid)
            identity.SetScopes(OpenIddictConstants.Scopes.Email,
                               OpenIddictConstants.Scopes.Profile,
                               OpenIddictConstants.Scopes.Roles);

            // Optionally log the claims
            foreach (var claim in identity.Claims)
            {
                _logger.LogInformation($"Claim: {claim.Type} = {claim.Value}");
            }

            // Create a new ClaimsPrincipal with the new identity
            var principal = new ClaimsPrincipal(identity);

            // Sign in with OpenIddict authentication scheme
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return BadRequest("Unsupported grant type.");
    }

    public class TokenRequestDto
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        _logger.LogInformation("User logging out.");

        await _signInManager.SignOutAsync();

        _logger.LogInformation("User logged out successfully.");
        return Ok("Logged out successfully.");
    }

    [HttpGet("test")]
    [Authorize]
    public IActionResult Test()
    {
        _logger.LogInformation("Test route accessed.");
        return Ok("Authenticated!");
    }
}
