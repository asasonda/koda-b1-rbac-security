using KodaStore.Application.Security;
using KodaStore.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace KodaStore.Infrastructure.Seeding;

public static class RoleSeedData
{
    public static async Task SeedAsync(RoleManager<IdentityRole<Guid>> roleManager, UserManager<AppUser> userManager, string? bootstrapAdminEmail)
    {
        string[] requiredRoles = [
            AppRole.Customer,
            AppRole.Admin
        ];

        foreach (var roleName in requiredRoles)
        {
            if(await roleManager.RoleExistsAsync(roleName))
            {
                continue;
            }

            var result = await roleManager.CreateAsync(new IdentityRole<Guid>
            {
                Name = roleName
            });

            EnsureSucceeded(
                result,
                $"Membuat role {roleName}"
            );
        }
        var existingUsers = await userManager.Users.ToListAsync();

        foreach (var user in existingUsers)
        {
            var roles = await userManager.GetRolesAsync(user);
            if(roles.Count > 0)
            {
                continue;
            }

            var result = await userManager.AddToRoleAsync(user, AppRole.Customer);
        }
    }

    private static void EnsureSucceeded(IdentityResult result, string operation)
    {
        if (result.Succeeded)
        {
            return;
        }

        var description = string.Join("; ", result.Errors.Select(error => error.Description));
        throw new InvalidOperationException($"{operation} gagal: {description}");
    }
}