using AlDar.Infrastructure;
using AlDar.Infrastructure.Identity;
using Serilog;



var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSwaggerServices();
builder.Services.AddCorsServices();

builder.AddAlDarLogging();

builder.Services.AddGlobalExceptionHandler();
builder.Services.AddInfrastructure(builder.Configuration);

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

app.UseAuthorization();

app.MapControllers();

app.Run();

// Exposes Program to WebApplicationFactory for integration tests.
public partial class Program
{

}