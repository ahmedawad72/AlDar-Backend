using AlDar.Infrastructure;
using AlDar.Infrastructure.Identity;
using Serilog;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddSwaggerServices();
builder.Services.AddCorsServices();

builder.AddAlDarLogging();

builder.Services.AddGlobalExceptionHandler();
builder.Services.AddInfrastructure(builder.Configuration);

builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";

    options.Cookie.Name = "aldar.csrf";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/api/auth";
});

var app = builder.Build();

if (!app.Environment.IsEnvironment("Testing"))
{
    using var scope = app.Services.CreateScope();

    await IdentitySeeder.SeedRolesAsync(
        scope.ServiceProvider);
}
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseSerilogRequestLogging();

app.UseExceptionHandler();

app.UseHttpsRedirection();

app.UseCors("AlDarClient");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// Exposes Program to WebApplicationFactory for integration tests.
public partial class Program
{

}