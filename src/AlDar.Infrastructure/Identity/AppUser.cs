using Microsoft.AspNetCore.Identity;

namespace AlDar.Infrastructure.Identity
{
    public class AppUser: IdentityUser
    {
        
        public string DisplayName { get; set; } = string.Empty;
        public string? ProfileImageUrl { get; set; }
    }
}
