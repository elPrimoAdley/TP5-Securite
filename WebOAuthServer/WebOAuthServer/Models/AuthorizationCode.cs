namespace WebOAuthServer.Models;

public class AuthorizationCode
{
    public string Code { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public DateTime Expiration { get; set; }
}