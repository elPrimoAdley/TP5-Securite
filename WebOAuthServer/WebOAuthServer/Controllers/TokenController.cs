using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebOAuthServer.Models;

namespace WebOAuthServer.Controllers;

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