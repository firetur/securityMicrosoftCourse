using Microsoft.EntityFrameworkCore;
using securityMicrosoftCourse.Models;

namespace securityMicrosoftCourse.Data;

public class AppDbContext : DbContext
{
    public DbSet<User> Users => Set<User>();

    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        if (!options.IsConfigured)
        {
            options.UseInMemoryDatabase("DefaultDB");
        }
    }
}