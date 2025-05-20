using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict;

namespace WebOAuthServer.Data
{
    public class AppDbContext : IdentityDbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        
        // Tables utilisées par OpenIddict
        public DbSet<OpenIddictEntityFrameworkCoreApplication> Applications { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreAuthorization> Authorizations { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreScope> Scopes { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreToken> Tokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.UseOpenIddict();
        }
    }
}