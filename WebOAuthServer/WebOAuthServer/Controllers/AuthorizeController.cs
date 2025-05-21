using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using WebOAuthServer.Models;

namespace WebOAuthServer.Controllers;

/*public static class InMemoryCodeStore
{
    public static ConcurrentDictionary<string, AuthorizationCode> Codes = new();
}

[Authorize]
public class AuthorizeController : Controller
{
    [HttpGet("/Authorize")]
    public IActionResult Authorize(string response_type,
        string client_id,
        string redirect_uri,
        string state)
    {
        if (response_type != "code")
        {
            return BadRequest("Seul response_type = code est supporté");
        }
        
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        
        // Génération du code d'autorisation
        var code = Guid.NewGuid().ToString("N");
        
        var authCode = new AuthorizationCode
        {
            Code = code,
            ClientId = client_id,
            RedirectUri = redirect_uri,
            Email = email,
            Expiration = DateTime.UtcNow.AddMinutes(5)
        };
        
        // Sauvegarde temporaire du code
        InMemoryCodeStore.Codes[code] = authCode;
        
        // Redirection avec le code et le state
        var uri = $"{redirect_uri}?code={code}&state={state}";
        return Redirect(uri);
    }

    */
    
[Authorize]
public class AuthorizeController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthorizeController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpGet("~/authorize")]
    public async Task<IActionResult> Authorize()
    {
        // Récupère la requête OpenIddict automatiquement (avec client_id, redirect_uri, etc.)
        var request = HttpContext.GetOpenIddictServerRequest();
        if (request is null)
            throw new InvalidOperationException("La requête OpenID Connect est introuvable.");
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
            return Challenge();

        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        // Ajoute les scopes demandés
        principal.SetScopes(request.GetScopes());

        // Ajoute les ressources (nom logique du resource server, déclaré dans la config)
        principal.SetResources("resource_server");

        // Ajoute le claim email (à inclure dans le JWT plus tard)
        //principal.SetClaim(OpenIddictConstants.Claims.Email, user.Email);
        principal.SetClaim(OpenIddictConstants.Claims.Email, user.Email, OpenIddictConstants.Destinations.AccessToken);
        
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}