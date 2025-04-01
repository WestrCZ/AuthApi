using Ardalis.GuardClauses;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ConnectController
        (
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        ILogger<ConnectController> logger
        ) : ControllerBase
    {
        /// <summary>
        /// Register a new user.
        /// </summary>
        /// <param name="registerDto">User registration data</param>
        /// <returns>Confirmation of successful registration</returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            logger.LogInformation("User registration attempted for: {Username}", registerDto.Username);

            var user = new IdentityUser { UserName = registerDto.Username, Email = registerDto.Email };

            var result = await userManager.CreateAsync(user, registerDto.Password);
            if (!result.Succeeded)
            {
                logger.LogWarning("User registration failed for: {Username}", registerDto.Username);
                return BadRequest(result.Errors);
            }

            logger.LogInformation("User registered successfully: {Username}", registerDto.Username);
            return Ok("User registered successfully.");
        }

        public class RegisterDto
        {
            public string? Username { get; set; }
            public string? Email { get; set; }
            public string? Password { get; set; }
        }

        /// <summary>
        /// Exchange username & password for a JWT token.
        /// </summary>
        /// <returns>A JWT token for the user</returns>
        [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            Guard.Against.Null(request, nameof(request));
            Guard.Against.Null(request.Username, nameof(request.Username));
            Guard.Against.Null(request.Password, nameof(request.Password));

            if (request.IsPasswordGrantType())
            {
                var user = await userManager.FindByNameAsync(request.Username);
                if (user == null)
                {
                    var properties = new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The username/password couple is invalid."
                    });

                    return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                // Validate the username/password parameters and ensure the account is not locked out.
                var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
                if (!result.Succeeded)
                {
                    var properties = new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The username/password couple is invalid."
                    });

                    return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens.
                identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                        .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                        .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                        .SetClaims(Claims.Role, [.. (await userManager.GetRolesAsync(user))])
                ;

                // Set the list of scopes granted to the client application.
                identity.SetScopes(new[]
                {
                Scopes.OpenId,
                Scopes.Email,
                Scopes.Profile,
                Scopes.Roles
            }.Intersect(request.GetScopes()));

                identity.SetDestinations(GetDestinations);

                var principal = new ClaimsPrincipal(identity);

                // Log claims again before SignIn
                foreach (var claim in principal.Claims)
                {
                    Console.WriteLine($"Final Claim in Principal: {claim.Type} = {claim.Value}");
                }

                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new NotImplementedException("The specified grant type is not implemented.");
        }

        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            switch (claim.Type)
            {
                case Claims.Name or Claims.PreferredUsername:
                    yield return Destinations.AccessToken;

                    if (claim.Subject != null && claim.Subject.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;

                    if (claim.Subject != null && claim.Subject.HasScope(Scopes.Email))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;

                    if (claim.Subject != null && claim.Subject.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;

                    yield break;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            logger.LogInformation("User logging out.");

            await signInManager.SignOutAsync();

            logger.LogInformation("User logged out successfully.");
            return Ok("Logged out successfully.");
        }

        [HttpGet("test")]
        [Authorize]
        public IActionResult Test()
        {
            logger.LogInformation("Test route accessed.");
            return Ok("Authenticated!");
        }
    }
}
