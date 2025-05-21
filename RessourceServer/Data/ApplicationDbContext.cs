using Microsoft.EntityFrameworkCore;
using RessourceServer.Models;

namespace RessourceServer.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions options) : base(options) { }

    public DbSet<User> Users { get; set; }
}