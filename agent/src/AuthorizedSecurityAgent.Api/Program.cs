using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using AuthorizedSecurityAgent.Api;
using AuthorizedSecurityAgent.Application.Contracts;
using AuthorizedSecurityAgent.Application.Scanning;
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
builder.Services
    .AddHttpClient<AuthorizedScanService>(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(20);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("AuthorizedSecurityAssessment/0.2");
    })
    .ConfigurePrimaryHttpMessageHandler(static () => new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy(AgentCorsPolicies.DevelopmentExtension, policy =>
    {
        policy
            .WithOrigins(agentSettings.AllowedDevelopmentOrigins)
            .WithMethods(HttpMethods.Get, HttpMethods.Post)
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
        var assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.2.0";

        return TypedResults.Ok(new AgentHealthResponse(
            Status: "healthy",
            Service: "authorized-security-agent",
            Version: assemblyVersion,
            UtcTimestamp: DateTimeOffset.UtcNow));
    })
    .WithName("AgentHealth")
    .WithDisplayName("Agent health check");

app.MapPost("/api/scans", async (
        ScanRequest request,
        AuthorizedScanService scanner,
        HttpContext context,
        CancellationToken cancellationToken) =>
    {
        context.Response.Headers.CacheControl = "no-store";

        try
        {
            var report = await scanner.TryScanAsync(request, cancellationToken);
            return report is null
                ? Results.Json(
                    new ErrorResponse(
                        ErrorCode: ErrorCodes.ForStatus(StatusCodes.Status429TooManyRequests),
                        Message: "Another assessment is already running.",
                        TraceId: context.TraceIdentifier),
                    statusCode: StatusCodes.Status429TooManyRequests)
                : Results.Ok(report);
        }
        catch (ScanValidationException exception)
        {
            return Results.BadRequest(new ErrorResponse(
                ErrorCode: ErrorCodes.ForStatus(StatusCodes.Status400BadRequest),
                Message: exception.Message,
                TraceId: context.TraceIdentifier));
        }
        catch (HttpRequestException)
        {
            return Results.BadRequest(new ErrorResponse(
                ErrorCode: "target-unreachable",
                Message: "The authorized target could not be reached safely.",
                TraceId: context.TraceIdentifier));
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Results.BadRequest(new ErrorResponse(
                ErrorCode: "target-timeout",
                Message: "The authorized target did not respond before the assessment timeout.",
                TraceId: context.TraceIdentifier));
        }
    })
    .WithName("StartAuthorizedScan")
    .WithDisplayName("Run authorized non-destructive assessment");

app.Logger.LogInformation(
    "Authorized Security Agent configured on loopback port {Port} in {EnvironmentName}",
    validatedOptions.Port,
    app.Environment.EnvironmentName);

app.Run();

namespace AuthorizedSecurityAgent.Api
{
    public partial class Program;
}
