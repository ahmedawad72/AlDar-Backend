using AlDar.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AlDar.Infrastructure.Persistence;

public class AlDarDbContext : IdentityDbContext<AppUser, IdentityRole, string>
{
    public AlDarDbContext(DbContextOptions<AlDarDbContext> options) : base(options) { }

}