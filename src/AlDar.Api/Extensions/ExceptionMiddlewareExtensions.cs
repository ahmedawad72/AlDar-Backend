using AlDar.Api.Middlewares;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ExceptionMiddlewareExtensions
    {
        public static IServiceCollection AddGlobalExceptionHandler(this IServiceCollection services)
        {
            services.AddExceptionHandler<GlobalExceptionHandlerMiddleware>();
            services.AddProblemDetails();
            return services;
        }
    }
}
