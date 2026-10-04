using System;
using System.Collections.Generic;
using System.Text;

namespace AlDar.Application.Authentication
{
    public sealed class ConfirmEmailRequest
    {
        public string UserId { get; set; } = string.Empty;

        public string Token { get; set; } = string.Empty;
    }
}
