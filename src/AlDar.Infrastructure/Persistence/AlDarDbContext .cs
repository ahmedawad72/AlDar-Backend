using AlDar.Infrastructure.Identity;
using AlDar.Infrastructure.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AlDar.Infrastructure.Persistence;

public class AlDarDbContext : IdentityDbContext<AppUser, IdentityRole, string>
{
    public AlDarDbContext(DbContextOptions<AlDarDbContext> options) : base(options) { }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.ApplyConfigurationsFromAssembly(typeof(AlDarDbContext).Assembly);
    }
}