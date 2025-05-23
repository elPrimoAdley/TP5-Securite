using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WebOAuthServer.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using static OpenIddict.Abstractions.OpenIddictConstants.Permissions;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

//Ajout connection a la BD
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    
    options.UseOpenIddict();
});

//Configuration du OpenIddict
builder.Services.AddOpenIddict()
    //Configure le stockage des données OpenIddict en utilisant la BD
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<AppDbContext>();
    })
    .AddServer(options =>
    {
        options.AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow();
        
        options.RegisterScopes("openid", "email", "profile", "api", "offline_access");
        
        // Définit les URI des endpoints OAuth
        options.SetAuthorizationEndpointUris("/authorize");
        options.SetTokenEndpointUris("/connect/token");
        options.SetConfigurationEndpointUris("/.well-known/openid-configuration");

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableStatusCodePagesIntegration()
            .DisableTransportSecurityRequirement(); //Autorise le HTTP

        
        options.AddDevelopmentSigningCertificate();
            //.AddSigningKey(new SymmetricSecurityKey(
            //    Encoding.UTF8.GetBytes("supersecretkey_for_token_signature")));

        options.AddEphemeralEncryptionKey()
            .DisableAccessTokenEncryption();// Optionnel pour lire les token sans avoir à les décrypter
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(2));
        options.SetRefreshTokenLifetime(TimeSpan.FromHours(24));
        //Signature des tokens
        options.AddDevelopmentEncryptionCertificate();
        //.AddDevelopmentSigningCertificate();
        
        options.IgnoreEndpointPermissions()
            .IgnoreGrantTypePermissions()
            .IgnoreScopePermissions()
            .IgnoreResponseTypePermissions();

    })
    //Configure la validation des tokens
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Enregistre les services de base pour ASP.NET Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

//Configure le comportement du cookie d’authentification. User non connectés => Login
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Auth/Login";
    options.ReturnUrlParameter = "returnUrl"; 

});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;

    var userManager = services.GetRequiredService<UserManager<IdentityUser>>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    var applicationManager = services.GetRequiredService<IOpenIddictApplicationManager>();

    string email = "test1@demo.com";
    string password = "Test1234!";

    var task = Task.Run(async () =>
    {
        var user = await userManager.FindByEmailAsync(email);
        if (user == null)
        {
            user = new IdentityUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                Console.WriteLine("Erreur lors de la création de l'utilisateur :");
                foreach (var error in result.Errors)
                    Console.WriteLine($" - {error.Description}");
            }
            else
            {
                Console.WriteLine("Utilisateur de test créé avec succès.");
            }
        }
        else
        {
            Console.WriteLine("Utilisateur de test déjà présent.");
        }

        if (await applicationManager.FindByClientIdAsync("web_client") is null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web_client",
                ClientSecret = "secret-web",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                DisplayName = "Client Web MVC",
                RedirectUris =
                {
                    new Uri("http://localhost:5174/signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("http://localhost:5174/signout-callback-oidc")
                },
                Permissions =
                {
                    Endpoints.Authorization,
                    Endpoints.Token,
                    GrantTypes.AuthorizationCode,
                    ResponseTypes.Code,

                    Prefixes.Scope + OpenIddictConstants.Scopes.Email,
                    Prefixes.Scope + OpenIddictConstants.Scopes.Profile,
                    Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
                    Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                    Prefixes.Scope + "api"
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
            });

            Console.WriteLine("Client web-client enregistré avec succès.");
        }
        else
        {
            Console.WriteLine("Client web-client déjà présent.");
        }
        
        if (await applicationManager.FindByClientIdAsync("desktop-client-v2") is null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "desktop-client-v2",
                DisplayName = "Desktop Client v2",
                ConsentType = OpenIddictConstants.ConsentTypes.Explicit,

                ClientType = OpenIddictConstants.ClientTypes.Public,
                RedirectUris = { new Uri("http://127.0.0.1:7890/") }, // Port utilisé par SystemBrowser

                Permissions =
                {
                    Endpoints.Authorization,
                    Endpoints.Token,
                    GrantTypes.AuthorizationCode,
                    ResponseTypes.Code,

                    Prefixes.Scope + OpenIddictConstants.Scopes.Email,
                    Prefixes.Scope + OpenIddictConstants.Scopes.Profile,
                    Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
                    Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                    "api" // Ton scope custom
                },

                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange // PKCE est requis pour les clients publics
                }
            });
        }
    });

    task.GetAwaiter().GetResult();
}

app.Run();
