using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using RessourceServer.Data;
using RessourceServer.Models;

namespace RessourceServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly ApplicationDbContext _db;

    public UserController(ApplicationDbContext db)
    {
        _db = db;
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        var emailClaim = User.FindFirst(ClaimTypes.Email)?.Value 
                         ?? User.FindFirst("email")?.Value;
        var email = User.Claims.FirstOrDefault(c => c.Type == OpenIddictConstants.Claims.Email)?.Value;

        //var email = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

        if (string.IsNullOrWhiteSpace(email))
        {
            return Unauthorized("Email claim not found.");
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
        {
            // Création utilisateur
            user = new User { Email = email };
            _db.Users.Add(user);
            await _db.SaveChangesAsync();
        }

        return Ok(new { user.Email, user.Id });
    }
}