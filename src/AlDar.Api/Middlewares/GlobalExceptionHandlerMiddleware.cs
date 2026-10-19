using AlDar.Application.Exceptions;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using static System.Net.WebRequestMethods;

namespace AlDar.Api.Middlewares
{
    public class GlobalExceptionHandlerMiddleware(ILogger<GlobalExceptionHandlerMiddleware> logger, IHostEnvironment env)
    : IExceptionHandler
    {
        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken ct)
        {
            var (statusCode, title) = exception switch
            {
                NotFoundException => (StatusCodes.Status404NotFound, "Not found"),
                InvalidCredentialsException => (StatusCodes.Status401Unauthorized, "Unauthorized"),
                EmailNotConfirmedException => (StatusCodes.Status403Forbidden, "Forbidden"),
                ForbiddenException => (StatusCodes.Status403Forbidden, "Forbidden"),
                ConflictException => (StatusCodes.Status409Conflict, "Conflict"),
                ValidationException => (StatusCodes.Status400BadRequest, "Validation failed"),
                AccountLockedException =>(StatusCodes.Status423Locked,"Account locked" ),
                _ => (StatusCodes.Status500InternalServerError, "Unexpected error")
            };

            // Log the real thing server-side, no matter what we tell the client.
            logger.LogError(exception, "{Title}: {Message}", title, exception.Message);

            var problem = new ProblemDetails
            {
                Status = statusCode,
                Title = title,
                Instance = httpContext.Request.Path,
                Detail = statusCode == StatusCodes.Status500InternalServerError && !env.IsDevelopment()
                    ? "Something went wrong. Please try again."   // never leak internals in prod
                    : exception.Message
            };
            problem.Extensions["traceId"] = httpContext.TraceIdentifier;

            if (exception is ValidationException v)
                problem.Extensions["errors"] = v.Errors;
            if (exception is EmailNotConfirmedException)
            {
                problem.Extensions["code"] =
                    EmailNotConfirmedException.ErrorCode;
            }

            if (exception is AccountLockedException accountLockedException)
            {
                problem.Extensions["code"] =
                    AccountLockedException.ErrorCode;

                if (accountLockedException.LockedUntilUtc.HasValue)
                {
                    problem.Extensions["lockedUntilUtc"] =
                        accountLockedException.LockedUntilUtc.Value;
                }
            }

            httpContext.Response.StatusCode = statusCode;
            await httpContext.Response.WriteAsJsonAsync(problem, ct);
            return true;
        }
    }
}
