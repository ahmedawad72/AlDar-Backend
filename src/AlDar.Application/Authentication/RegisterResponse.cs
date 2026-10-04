using System;
using System.Collections.Generic;
using System.Text;

namespace AlDar.Application.Authentication
{
    public sealed class RegisterResponse
    {
        public string Id { get; init; } = string.Empty;
        public string Email { get; init; } = string.Empty;
        public string DisplayName { get; init; } = string.Empty;
        public string Role { get; init; } = string.Empty;
        public bool ConfirmationEmailSent { get; init; }
    }
}
