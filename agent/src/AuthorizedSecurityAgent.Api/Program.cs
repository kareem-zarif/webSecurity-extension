using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using AuthorizedSecurityAgent.Api;
using AuthorizedSecurityAgent.Application.Contracts;
using AuthorizedSecurityAgent.Infrastructure.Errors;
using AuthorizedSecurityAgent.Infrastructure.Logging;
using AuthorizedSecurityAgent.Infrastructure.Middleware;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
var agentSettings = builder.Configuration
    .GetRequiredSection(AgentOptions.SectionName)
    .Get<AgentOptions>() ?? throw new InvalidOperationException("Agent configuration is missing.");

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.ListenLocalhost(agentSettings.Port);
});

builder.Logging.ClearProviders();
builder.Services.AddSingleton<ISensitiveDataRedactor, SensitiveDataRedactor>();
builder.Services.AddSingleton<ILoggerProvider, RedactingJsonConsoleLoggerProvider>();

builder.Services
    .AddOptions<AgentOptions>()
    .BindConfiguration(AgentOptions.SectionName)
    .ValidateDataAnnotations()
    .Validate(
        static options => options.AllowedDevelopmentOrigins.All(AgentOptions.IsLoopbackOrigin),
        "Development origins must use HTTP(S) on a loopback host without credentials, paths, queries, or fragments.")
    .ValidateOnStart();

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower));
});

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

builder.Services.AddCors(options =>
{
    options.AddPolicy(AgentCorsPolicies.DevelopmentExtension, policy =>
    {
        policy
            .WithOrigins(agentSettings.AllowedDevelopmentOrigins)
            .WithMethods(HttpMethods.Get)
            .WithHeaders("Accept", "Content-Type");
    });
});

var app = builder.Build();
var validatedOptions = app.Services.GetRequiredService<IOptions<AgentOptions>>().Value;

app.UseMiddleware<SafeRequestLoggingMiddleware>();
app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.UseCors(AgentCorsPolicies.DevelopmentExtension);
}

app.UseStatusCodePages(async statusCodeContext =>
{
    var context = statusCodeContext.HttpContext;
    var response = new ErrorResponse(
        ErrorCode: ErrorCodes.ForStatus(context.Response.StatusCode),
        Message: ErrorMessages.ForStatus(context.Response.StatusCode),
        TraceId: context.TraceIdentifier);

    await context.Response.WriteAsJsonAsync(response, context.RequestAborted);
});

app.MapGet("/health", (HttpContext context) =>
    {
        context.Response.Headers.CacheControl = "no-store";
        var assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";

        return TypedResults.Ok(new AgentHealthResponse(
            Status: "healthy",
            Service: "authorized-security-agent",
            Version: assemblyVersion,
            UtcTimestamp: DateTimeOffset.UtcNow));
    })
    .WithName("AgentHealth")
    .WithDisplayName("Agent health check");

app.Logger.LogInformation(
    "Authorized Security Agent configured on loopback port {Port} in {EnvironmentName}",
    validatedOptions.Port,
    app.Environment.EnvironmentName);

app.Run();

namespace AuthorizedSecurityAgent.Api
{
    public partial class Program;
}

