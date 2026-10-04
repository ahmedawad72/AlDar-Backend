
namespace Microsoft.Extensions.DependencyInjection
    // to use service automatically without any need to use this namespace in program.cs
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddSwaggerServices(this IServiceCollection services)
        {
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(options =>
                    options.SwaggerDoc("v1", new() { Title = "AlDar API", Version = "v1" }   )
                );
            return services;
        }

        public static IServiceCollection AddCorsServices(this IServiceCollection services)
        {
            services.AddCors(options =>
            {
                 options.AddPolicy("AlDarClient", policy =>
                        policy.WithOrigins("http://localhost:4200")
                              .AllowAnyHeader()
                              .AllowAnyMethod());
            });

            return services;
        }
    }
}
