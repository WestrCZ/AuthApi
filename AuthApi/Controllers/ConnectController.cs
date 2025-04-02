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
    public async Task<IActionResult> Exchange([FromForm] TokenRequestDto tokenRequestDto)
    {
        _logger.LogInformation("Token exchange requested for user: {Username}", tokenRequestDto.Username);

        // Validate the incoming token request
        if (string.IsNullOrEmpty(tokenRequestDto.Username) || string.IsNullOrEmpty(tokenRequestDto.Password))
        {
            return BadRequest("Username and password are required.");
        }

        // Find the user by username
        var user = await _userManager.FindByNameAsync(tokenRequestDto.Username);
        if (user == null)
        {
            _logger.LogWarning("Token exchange failed for: {Username} - User not found", tokenRequestDto.Username);
            return Unauthorized("Invalid username or password.");
        }

        // Check if the password is correct
        var result = await _signInManager.PasswordSignInAsync(user, tokenRequestDto.Password, false, false);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Token exchange failed for: {Username} - Invalid credentials", tokenRequestDto.Username);
            return Unauthorized("Invalid username or password.");
        }

        _logger.LogInformation("User {Username} successfully authenticated. Generating token.", tokenRequestDto.Username);

        // Generate the token
        var claims = new[]
        {
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.Email, user.Email),
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your_secret_key_here"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "your_issuer_here",
            audience: "your_audience_here",
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: creds
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Ok(new { access_token = tokenString, token_type = "bearer", expires_in = 3600 });
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
