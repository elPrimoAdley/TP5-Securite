using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WebOAuthServer.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;

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
        
        // Définit les URI des endpoints OAuth
        options.SetAuthorizationEndpointUris("/connect/authorize");
        options.SetTokenEndpointUris("/connect/token")
            .SetConfigurationEndpointUris("/.well-known/openid-configuration");;

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableStatusCodePagesIntegration();


        options.AddEphemeralEncryptionKey();
        options.AddDevelopmentEncryptionCertificate();
        options.AddDevelopmentSigningCertificate(); 
            //.AddSigningKey(new SymmetricSecurityKey(
            //    Encoding.UTF8.GetBytes("supersecretkey_for_token_signature")));

        options.AddEphemeralEncryptionKey()
            .AddEphemeralEncryptionKey()
            .DisableAccessTokenEncryption();
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(2));
        options.SetRefreshTokenLifetime(TimeSpan.FromHours(24));
        //Signature des tokens
        options.AddDevelopmentEncryptionCertificate();
        //.AddDevelopmentSigningCertificate();

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

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;

    var userManager = services.GetRequiredService<UserManager<IdentityUser>>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

    string email = "test@demo.com";
    string password = "Test123!";

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
    
    
}


app.Run();
