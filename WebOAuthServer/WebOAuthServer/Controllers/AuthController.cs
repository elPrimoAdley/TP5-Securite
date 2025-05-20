using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace WebOAuthServer.Controllers;

public class AuthController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpGet]
    public IActionResult Login(string returnUrl)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    public async Task<IActionResult> Login(string email, string password, string returnUrl)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var result = await _signInManager.PasswordSignInAsync(user, password, false, false);
            if (result.Succeeded)
            {
                return Redirect(returnUrl);
            }
            
            //Sauvegarder l'email de l'utilisateur dans les claims 
            await _signInManager.SignInWithClaimsAsync(user, false, new List<Claim>
            {
                new Claim(ClaimTypes.Email, email)
            });
        }

        ViewBag.Error = "email ou mot de passe invalide";
        ViewBag["ReturnUrl"] = returnUrl;
        return View();
    }
}