using System;
using System.Collections.Generic;
using System.Text;

namespace AlDar.Application.Exceptions
{
    public sealed class ForbiddenException : Exception
    {
        public ForbiddenException(string message = "You do not have permission to perform this action.")
       : base(message) { }
    }
}
