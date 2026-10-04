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
                ForbiddenException => (StatusCodes.Status403Forbidden, "Forbidden"),
                ConflictException => (StatusCodes.Status409Conflict, "Conflict"),
                ValidationException => (StatusCodes.Status400BadRequest, "Validation failed"),
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

            httpContext.Response.StatusCode = statusCode;
            await httpContext.Response.WriteAsJsonAsync(problem, ct);
            return true;
        }
    }
}
