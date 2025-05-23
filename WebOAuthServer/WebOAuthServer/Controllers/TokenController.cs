using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using WebOAuthServer.Models;

namespace WebOAuthServer.Controllers;

[ApiController]
public class TokenController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public TokenController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager   = userManager;
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        // 1) Récupère l’objet OpenIddictServerRequest
        var request = HttpContext.GetOpenIddictServerRequest()
                   ?? throw new InvalidOperationException("Requête introuvable.");

        ClaimsPrincipal principal;

        // 2) Selon le grant type, on reconstitue le principal
        if (request.IsAuthorizationCodeGrantType())
        {
            // On valide le code via OpenIddict (il retrouve le principal original)
            principal = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
                              .ContinueWith(t => t.Result.Principal);
        }
        else if (request.IsRefreshTokenGrantType())
        {
            // Même idée pour le refresh token
            principal = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)
                              .ContinueWith(t => t.Result.Principal);
        }
        else
        {
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // 3) Récupère l’utilisateur pour ajouter des claims custom
        var userId = principal.GetClaim(OpenIddictConstants.Claims.Subject);
        var user   = await _userManager.FindByIdAsync(userId);

        // 4) Crée un nouveau principal “rafraîchi”  
        var newPrincipal = await _signInManager.CreateUserPrincipalAsync(user);

        // Transfère les scopes et destinations
        newPrincipal.SetScopes(principal.GetScopes());
        newPrincipal.SetResources("resource_server");

        // Ajoute un claim email dans l’Access Token
        newPrincipal.SetClaim(
            OpenIddictConstants.Claims.Email,
            user.Email,
            OpenIddictConstants.Destinations.AccessToken
        );

        // 5) Configure la durée des tokens si tu veux l’ajuster dynamiquement
        var now = DateTimeOffset.UtcNow;
        newPrincipal.SetAccessTokenLifetime(TimeSpan.FromMinutes(2));
        newPrincipal.SetRefreshTokenLifetime(TimeSpan.FromHours(24));

        // 6) Renvoie le SignIn principal : OpenIddict en fait le JSON
        return SignIn(
            newPrincipal,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
    }
}
/*[Microsoft.AspNetCore.Components.Route("token")]
[ApiController]
public class TokenController : ControllerBase
{
    // Conserve une liste des refresh tokens
    private static Dictionary<string, string> _refreshTokens = new();
    
    [HttpPost]
    public IActionResult Token([FromForm] string code, [FromForm] string client_id, [FromForm] string redirect_uri)
    {
        // Vérifier si le code d'autorisation est valide
        if (!InMemoryCodeStore.Codes.TryGetValue(code, out var authInfo))
        {
            return BadRequest(new { error = "invalid_grant", error_description = "Code d'autorisation invalide ou expire" });
        }

        // Vérifier expiration
        if (authInfo.Expiration < DateTime.UtcNow)
        {
            return BadRequest(new { error = "invalid_grant", error_description = "Le code d'authorisation a expire" });
        }

        // Génération du access token (JWT)
        var accessToken = GenerateJwtToken(authInfo.Email);

        // Génération du refresh token
        var refreshToken = Guid.NewGuid().ToString();
        _refreshTokens[refreshToken] = authInfo.Email;

        // Supprimer le code d'autorisation pour qu'il ne soit plus utilisable
        //InMemoryCodeStore.Codes.Remove(code);

        return Ok(new
        {
            access_token = accessToken,
            token_type = "bearer",
            expires_in = 120, // 2 minutes
            refresh_token = refreshToken
        });
    }
    
    private string GenerateJwtToken(string email)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, email),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("supersecretkey_for_token_signature"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var issuer = $"{Request.Scheme}://{Request.Host.Value}";

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: "resource_server",
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(2),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
}
*/