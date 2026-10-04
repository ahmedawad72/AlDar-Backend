using AlDar.Domain.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AlDar.Infrastructure.Identity;

public static class IdentitySeeder
{
    public static async Task SeedRolesAsync( IServiceProvider service)
    {
            var roles = new[]
            {
                Roles.Admin,
                Roles.Teacher,
                Roles.Student
            };

        var roleManager = service.GetService<RoleManager<IdentityRole>>();
        foreach (var role in roles)
        {
            if (await roleManager.RoleExistsAsync(role))
                continue;
          
            var result = await roleManager.CreateAsync( new IdentityRole(role));

            if (!result.Succeeded)
            {
                var errors = string.Join(
                    ", ",
                    result.Errors.Select(e => e.Description));

                throw new InvalidOperationException(
                    $"Failed to create role '{role}': {errors}");
            }
        }
    }

}