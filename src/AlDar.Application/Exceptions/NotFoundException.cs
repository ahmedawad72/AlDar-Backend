using System;
using System.Collections.Generic;
using System.Text;

namespace AlDar.Application.Exceptions
{
    public sealed class NotFoundException : Exception
    {
        public NotFoundException(string entityName, object key)
         : base($"{entityName} with id '{key}' was not found.") { }
    }
}
