using Serilog;
using Serilog.Events;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class LoggingExtensions
    {
        public static void AddAlDarLogging(this WebApplicationBuilder builder)
        {
            builder.Host.UseSerilog((context, services, configuration) => configuration
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning) // quiets routine request noise
                .Enrich.FromLogContext()
                .ReadFrom.Services(services)
                .WriteTo.Console()
                .WriteTo.File(
                    path: "logs/log-.txt",
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 14,  // ~2 weeks, so logs don't quietly fill the VPS disk
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}"));
        }
    }
}
