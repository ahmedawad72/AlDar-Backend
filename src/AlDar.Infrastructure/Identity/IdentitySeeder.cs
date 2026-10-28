using AlDar.Domain.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AlDar.Infrastructure.Identity;

public static class IdentitySeeder
{
    public static async Task SeedRolesAsync(IServiceProvider serviceProvider)
    {
        var roles = new[]
        {
            Roles.Admin,
            Roles.Teacher,
            Roles.Student
        };

        var roleManager =
            serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        foreach (var role in roles)
        {
            if (await roleManager.RoleExistsAsync(role))
                continue;

            var result =
                await roleManager.CreateAsync(
                    new IdentityRole(role));

            if (result.Succeeded)
                continue;

            var errors =
                string.Join(
                    ", ",
                    result.Errors.Select(
                        error => error.Description));

            throw new InvalidOperationException(
                $"Failed to create role '{role}': {errors}");
        }
    }
}