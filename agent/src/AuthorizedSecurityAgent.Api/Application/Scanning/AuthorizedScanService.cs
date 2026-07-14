using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using AuthorizedSecurityAgent.Application.Contracts;

namespace AuthorizedSecurityAgent.Application.Scanning;

internal sealed partial class AuthorizedScanService(HttpClient httpClient)
{
    private const int MaximumResponseBytes = 1_000_000;
    private const int MaximumRedirects = 5;
    private const int ProbeDelayMilliseconds = 200;
    private const string ProbeOrigin = "https://security-probe.invalid";

    private static readonly IReadOnlyList<string> ChecksPerformed =
    [
        "Transport encryption and HTTPS",
        "HTTP Strict Transport Security (HSTS)",
        "Content Security Policy (CSP)",
        "Clickjacking protection",
        "MIME sniffing protection",
        "Referrer and browser feature policies",
        "Cookie security attributes",
        "Cross-origin resource sharing headers",
        "Technology disclosure headers",
        "Mixed active and passive content",
        "Insecure form submission",
        "External script integrity metadata"
    ];

    private static readonly IReadOnlyList<string> ActiveChecksPerformed =
    [
        "Arbitrary CORS-origin reflection",
        "Cross-origin method authorization",
        "HTTP TRACE exposure",
        "Unencoded HTML reflection canary",
        "Database error response to an injection canary",
        "Open redirect parameters"
    ];

    private static readonly Uri OwaspHeadersReference =
        new("https://owasp.org/www-project-secure-headers/");
    private static readonly Uri OwaspTransportReference =
        new("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security");
    private static readonly Uri OwaspCookieReference =
        new("https://owasp.org/www-community/controls/SecureCookieAttribute");

    private readonly SemaphoreSlim scanLock = new(1, 1);

    public async Task<ScanReport?> TryScanAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        if (!await scanLock.WaitAsync(0, cancellationToken))
        {
            return null;
        }

        try
        {
            return await ScanAsync(request, cancellationToken);
        }
        finally
        {
            scanLock.Release();
        }
    }

    private async Task<ScanReport> ScanAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        var target = await ValidateRequestAsync(request, cancellationToken);
        var scanId = Guid.NewGuid();
        var startedAt = DateTimeOffset.UtcNow;
        var findings = new List<Finding>();

        var targetFetch = await GetTargetAsync(target, cancellationToken);
        using var response = targetFetch.Response;
        var assessedUrl = response.RequestMessage?.RequestUri ?? target;
        var detectedAt = DateTimeOffset.UtcNow;
        string? baselineBody = null;

        EvaluateTransport(assessedUrl, scanId, detectedAt, findings);
        EvaluateHeaders(response, assessedUrl, scanId, detectedAt, findings);
        EvaluateCookies(response, assessedUrl, scanId, detectedAt, findings);

        if (IsHtml(response.Content.Headers.ContentType))
        {
            baselineBody = await ReadLimitedBodyAsync(response.Content, cancellationToken);
            EvaluateHtml(baselineBody, assessedUrl, scanId, detectedAt, findings);
        }

        var requestsSent = targetFetch.RequestsSent;
        if (request.Mode == ScanMode.ActiveVerification)
        {
            requestsSent += await RunActiveVerificationAsync(
                RedactToOrigin(assessedUrl),
                baselineBody ?? string.Empty,
                scanId,
                findings,
                cancellationToken);
        }

        var checks = request.Mode == ScanMode.ActiveVerification
            ? ChecksPerformed.Concat(ActiveChecksPerformed).ToArray()
            : ChecksPerformed;

        findings.Sort(static (left, right) => SeverityRank(right.Severity).CompareTo(SeverityRank(left.Severity)));
        var completedAt = DateTimeOffset.UtcNow;

        return new ScanReport(
            ScanId: scanId,
            TargetUrl: RedactToOrigin(assessedUrl),
            Mode: request.Mode,
            StartedAt: startedAt,
            CompletedAt: completedAt,
            Summary: BuildSummary(findings, checks.Count, requestsSent),
            ChecksPerformed: checks,
            Findings: findings,
            ScopeNote: request.Mode == ScanMode.ActiveVerification
                ? "Unauthenticated, rate-limited active verification of one explicitly authorized origin. Harmless canaries and non-mutating HTTP methods were used. No credentials, browser cookies, data extraction, script execution, brute force, persistence, destructive requests, or denial-of-service techniques were used."
                : "Unauthenticated, non-destructive baseline assessment of one explicitly authorized origin. No credentials, browser cookies, active canaries, brute force, persistence, or denial-of-service techniques were used.");
    }

    private async Task<Uri> ValidateRequestAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        if (request.ContractVersion != ContractVersion.Current)
        {
            throw new ScanValidationException("The scan contract version is not supported.");
        }

        if (!request.AuthorizationConfirmed)
        {
            throw new ScanValidationException("Explicit authorization confirmation is required.");
        }

        if (request.Mode == ScanMode.ActiveVerification && !request.ActiveVerificationConfirmed)
        {
            throw new ScanValidationException("Active verification requires a separate explicit confirmation.");
        }

        if (!TryParseOrigin(request.TargetUrl, out var target) ||
            !TryParseOrigin(request.AuthorizedOrigin, out var authorizedOrigin))
        {
            throw new ScanValidationException("The target and authorized origin must be an HTTP(S) origin without credentials, paths, queries, or fragments.");
        }

        if (!Uri.Compare(target, authorizedOrigin, UriComponents.SchemeAndServer, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase).Equals(0))
        {
            throw new ScanValidationException("The target must exactly match the origin that was authorized.");
        }

        await ValidateResolvedAddressesAsync(target, cancellationToken);
        return target;
    }

    private async Task<TargetFetch> GetTargetAsync(Uri target, CancellationToken cancellationToken)
    {
        var current = target;
        var requestsSent = 0;

        for (var redirectCount = 0; redirectCount <= MaximumRedirects; redirectCount++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml", 0.9));

            var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
            requestsSent++;

            if (!IsRedirect(response.StatusCode) || response.Headers.Location is null)
            {
                return new TargetFetch(response, requestsSent);
            }

            var redirect = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(current, response.Headers.Location);

            if (!IsSameOrigin(target, redirect))
            {
                return new TargetFetch(response, requestsSent);
            }

            response.Dispose();
            current = redirect;
        }

        throw new ScanValidationException("The target exceeded the safe redirect limit.");
    }

    private async Task<int> RunActiveVerificationAsync(
        Uri target,
        string baselineBody,
        Guid scanId,
        ICollection<Finding> findings,
        CancellationToken cancellationToken)
    {
        var detectedAt = DateTimeOffset.UtcNow;
        var requestsSent = 0;

        var corsGet = await SendProbeAsync(
            HttpMethod.Get,
            target,
            static request => request.Headers.TryAddWithoutValidation("Origin", ProbeOrigin),
            readBody: false,
            cancellationToken);
        requestsSent++;

        var corsOptions = await SendProbeAsync(
            HttpMethod.Options,
            target,
            static request =>
            {
                request.Headers.TryAddWithoutValidation("Origin", ProbeOrigin);
                request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "DELETE");
            },
            readBody: false,
            cancellationToken);
        requestsSent++;

        EvaluateActiveCors(corsGet, corsOptions, target, scanId, detectedAt, findings);

        var trace = await SendProbeAsync(
            new HttpMethod("TRACE"),
            target,
            configure: null,
            readBody: false,
            cancellationToken);
        requestsSent++;
        if ((int)trace.StatusCode is >= 200 and < 300)
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "active-trace-enabled", "HTTP TRACE is enabled",
                "HTTP Method Security", Severity.Low, Confidence.High,
                $"A TRACE request returned HTTP {(int)trace.StatusCode}. The response body was not retained.",
                "TRACE is rarely required and increases unnecessary HTTP-method exposure. Legacy clients may combine it with other weaknesses to disclose request data.",
                "Disable TRACE at the web server, reverse proxy, and application platform unless there is a documented operational requirement.",
                OwaspHeadersReference,
                "Sent one unauthenticated TRACE request without cookies, credentials, or custom sensitive headers. Considered the method enabled only when it returned a 2xx response."));
        }

        var token = Guid.NewGuid().ToString("N");
        var htmlCanary = $"<as-probe data-token=\"{token}\">probe</as-probe>";
        var reflectionProbe = await SendProbeAsync(
            HttpMethod.Get,
            BuildProbeUri(target, "as_probe", htmlCanary),
            configure: null,
            readBody: true,
            cancellationToken);
        requestsSent++;
        if (reflectionProbe.Body.Contains(htmlCanary, StringComparison.Ordinal))
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "active-unencoded-reflection", "Input is reflected into HTML without encoding",
                "Input Handling", Severity.Medium, Confidence.Medium,
                "A harmless custom-element canary supplied in the as_probe query parameter was returned byte-for-byte in the HTML response. The response content was not retained.",
                "Unencoded reflection can become cross-site scripting when attacker-controlled markup reaches an executable HTML, attribute, URL, or script context.",
                "Apply context-appropriate output encoding, validate input by expected type, and enforce a restrictive CSP as defense in depth. Manually verify the exact reflection context before assigning final severity.",
                new Uri("https://owasp.org/www-community/attacks/xss/"),
                "Sent one GET request with a non-executable <as-probe> custom element in the as_probe query parameter. No event handler or JavaScript was included or executed. Compared the response for an exact unencoded reflection."));
        }

        var baselineSqlSignature = DetectSqlErrorFamily(baselineBody);
        var sqlProbe = await SendProbeAsync(
            HttpMethod.Get,
            BuildProbeUri(target, "as_probe", "'"),
            configure: null,
            readBody: true,
            cancellationToken);
        requestsSent++;
        var probeSqlSignature = DetectSqlErrorFamily(sqlProbe.Body);
        if (probeSqlSignature is not null && !string.Equals(probeSqlSignature, baselineSqlSignature, StringComparison.Ordinal))
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "active-database-error", "Input triggered a database error signature",
                "Injection", Severity.High, Confidence.Medium,
                $"A single-quote canary caused a {probeSqlSignature} error signature that was not present in the baseline response. No database content was extracted or retained.",
                "A database error caused by untrusted input can indicate unsafe query construction and may expose a SQL injection path.",
                "Use parameterized queries for every database operation, avoid string-built SQL, return generic production errors, and manually reproduce in a controlled test environment before final client reporting.",
                new Uri("https://owasp.org/www-community/attacks/SQL_Injection"),
                "Sent one GET request with a single quote in the as_probe query parameter, then compared only known database-error signatures against the baseline response. Did not use UNION, time-delay, boolean extraction, schema discovery, or data-retrieval payloads."));
        }

        foreach (var parameter in new[] { "redirect", "next", "returnUrl" })
        {
            var redirectDestination = $"{ProbeOrigin}/{token}";
            var redirectProbe = await SendProbeAsync(
                HttpMethod.Get,
                BuildProbeUri(target, parameter, redirectDestination),
                configure: null,
                readBody: false,
                cancellationToken);
            requestsSent++;

            if (redirectProbe.Location is null ||
                !Uri.TryCreate(target, redirectProbe.Location, out var location) ||
                !string.Equals(location.Host, "security-probe.invalid", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(CreateFinding(
                scanId, target, detectedAt, "active-open-redirect", "Untrusted input controls an external redirect",
                "Redirect Validation", Severity.Medium, Confidence.High,
                $"The {parameter} query parameter produced a redirect to the controlled security-probe.invalid origin. The redirect was not followed.",
                "Open redirects can support phishing, authorization-code leakage, and security-control bypasses by making an attacker destination appear to begin on a trusted domain.",
                "Allow only local relative paths or validate destinations against a strict server-side allowlist. Reject scheme-relative URLs, encoded bypasses, and userinfo-based URLs.",
                new Uri("https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"),
                $"Sent one GET request with {parameter}=https://security-probe.invalid/<random-token>. Automatic redirects were disabled and no request was sent to the external destination."));
            break;
        }

        return requestsSent;
    }

    private static void EvaluateActiveCors(
        ProbeResult getProbe,
        ProbeResult optionsProbe,
        Uri target,
        Guid scanId,
        DateTimeOffset detectedAt,
        ICollection<Finding> findings)
    {
        var reflectsProbeOrigin = string.Equals(getProbe.AllowOrigin, ProbeOrigin, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(optionsProbe.AllowOrigin, ProbeOrigin, StringComparison.OrdinalIgnoreCase);
        if (!reflectsProbeOrigin)
        {
            return;
        }

        var allowsCredentials = string.Equals(getProbe.AllowCredentials, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(optionsProbe.AllowCredentials, "true", StringComparison.OrdinalIgnoreCase);
        var allowsDelete = optionsProbe.AllowMethods?.Split(',', StringSplitOptions.TrimEntries)
            .Contains("DELETE", StringComparer.OrdinalIgnoreCase) == true;
        var severity = allowsCredentials ? Severity.High : Severity.Medium;

        findings.Add(CreateFinding(
            scanId, target, detectedAt, "active-cors-origin-reflection", "CORS trusts an arbitrary external origin",
            "Cross-Origin Resource Sharing", severity, Confidence.High,
            $"The server reflected the controlled Origin {ProbeOrigin}. Credentials allowed: {allowsCredentials}. DELETE advertised by preflight: {allowsDelete}.",
            "An attacker-controlled website may be able to read cross-origin responses. If credentials are allowed or sensitive unauthenticated data is returned, this can expose protected application information or actions.",
            "Use a strict server-side allowlist of required origins, never reflect arbitrary Origin values, enable credentials only when necessary, and authorize every endpoint independently of CORS.",
            new Uri("https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"),
            "Sent one credential-free GET and one OPTIONS preflight using Origin: https://security-probe.invalid. Checked whether that arbitrary origin was reflected and whether credentials or DELETE were authorized. No DELETE request was sent."));
    }

    private async Task<ProbeResult> SendProbeAsync(
        HttpMethod method,
        Uri target,
        Action<HttpRequestMessage>? configure,
        bool readBody,
        CancellationToken cancellationToken)
    {
        await Task.Delay(ProbeDelayMilliseconds, cancellationToken);
        using var request = new HttpRequestMessage(method, target);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        configure?.Invoke(request);

        using var response = await httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        var body = readBody
            ? await ReadLimitedBodyAsync(response.Content, cancellationToken)
            : string.Empty;

        return new ProbeResult(
            StatusCode: response.StatusCode,
            Location: response.Headers.Location,
            Body: body,
            AllowOrigin: Header(response, "Access-Control-Allow-Origin"),
            AllowCredentials: Header(response, "Access-Control-Allow-Credentials"),
            AllowMethods: Header(response, "Access-Control-Allow-Methods"));
    }

    private static Uri BuildProbeUri(Uri origin, string parameter, string value)
    {
        var builder = new UriBuilder(origin)
        {
            Query = $"{Uri.EscapeDataString(parameter)}={Uri.EscapeDataString(value)}"
        };
        return builder.Uri;
    }

    private static string? DetectSqlErrorFamily(string body)
    {
        if (MySqlErrorRegex().IsMatch(body))
        {
            return "MySQL-style";
        }

        if (PostgreSqlErrorRegex().IsMatch(body))
        {
            return "PostgreSQL-style";
        }

        if (SqlServerErrorRegex().IsMatch(body))
        {
            return "SQL Server-style";
        }

        if (OracleErrorRegex().IsMatch(body))
        {
            return "Oracle-style";
        }

        if (SqliteErrorRegex().IsMatch(body))
        {
            return "SQLite-style";
        }

        return null;
    }

    private static void EvaluateTransport(
        Uri target,
        Guid scanId,
        DateTimeOffset detectedAt,
        ICollection<Finding> findings)
    {
        if (target.Scheme == Uri.UriSchemeHttp && !target.IsLoopback)
        {
            findings.Add(CreateFinding(
                scanId,
                target,
                detectedAt,
                "transport-http",
                "Website is served without HTTPS",
                "Transport Security",
                Severity.High,
                Confidence.High,
                "The authorized origin uses plain HTTP.",
                "Network attackers can observe or modify traffic, including submitted data and application responses.",
                "Redirect all HTTP traffic to HTTPS, deploy a valid certificate, and enable HSTS after confirming every required subdomain supports HTTPS.",
                OwaspTransportReference));
        }
    }

    private static void EvaluateHeaders(
        HttpResponseMessage response,
        Uri target,
        Guid scanId,
        DateTimeOffset detectedAt,
        ICollection<Finding> findings)
    {
        var csp = Header(response, "Content-Security-Policy");

        if (target.Scheme == Uri.UriSchemeHttps)
        {
            var hsts = Header(response, "Strict-Transport-Security");
            if (hsts is null)
            {
                findings.Add(HeaderFinding(
                    scanId, target, detectedAt, "header-hsts-missing", "HSTS header is missing",
                    Severity.Medium, "Strict-Transport-Security was not present on the HTTPS response.",
                    "Browsers can be exposed to protocol-downgrade attempts before a secure connection is established.",
                    "Add Strict-Transport-Security with an appropriate max-age. Add includeSubDomains or preload only after validating the full domain estate."));
            }
            else if (HstsDisabledRegex().IsMatch(hsts))
            {
                findings.Add(HeaderFinding(
                    scanId, target, detectedAt, "header-hsts-disabled", "HSTS is explicitly disabled",
                    Severity.Medium, "Strict-Transport-Security uses max-age=0.",
                    "The response removes the browser's remembered HTTPS-only policy.",
                    "Set a positive HSTS max-age after confirming HTTPS is consistently available."));
            }
        }

        if (csp is null)
        {
            findings.Add(HeaderFinding(
                scanId, target, detectedAt, "header-csp-missing", "Content Security Policy is missing",
                Severity.Medium, "Content-Security-Policy was not present.",
                "The browser has fewer restrictions on where scripts and other active content may load from, increasing the impact of an injection flaw.",
                "Deploy a restrictive Content-Security-Policy. Start with Report-Only, remove unsafe sources, then enforce the validated policy."));
        }
        else if (CspUnsafeScriptRegex().IsMatch(csp))
        {
            findings.Add(HeaderFinding(
                scanId, target, detectedAt, "header-csp-unsafe-script", "CSP permits unsafe script execution",
                Severity.Medium, "The script-src policy contains unsafe-inline or unsafe-eval.",
                "Permissive script directives weaken CSP protection against script injection.",
                "Replace unsafe-inline with nonces or hashes and remove unsafe-eval after updating incompatible scripts."));
        }

        var hasFrameAncestors = csp is not null && CspFrameAncestorsRegex().IsMatch(csp);
        if (Header(response, "X-Frame-Options") is null && !hasFrameAncestors)
        {
            findings.Add(HeaderFinding(
                scanId, target, detectedAt, "header-framing-missing", "Clickjacking protection is missing",
                Severity.Medium, "Neither X-Frame-Options nor CSP frame-ancestors was present.",
                "Another site may be able to frame this page and trick a user into interacting with concealed controls.",
                "Set CSP frame-ancestors to the required trusted origins. Use X-Frame-Options as a legacy compatibility layer when appropriate."));
        }

        if (!string.Equals(Header(response, "X-Content-Type-Options"), "nosniff", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(HeaderFinding(
                scanId, target, detectedAt, "header-nosniff-missing", "MIME sniffing protection is missing",
                Severity.Low, "X-Content-Type-Options: nosniff was not present.",
                "Some browsers may interpret a response as a more dangerous content type than the server declared.",
                "Send X-Content-Type-Options: nosniff on application responses and static assets."));
        }

        if (Header(response, "Referrer-Policy") is null)
        {
            findings.Add(HeaderFinding(
                scanId, target, detectedAt, "header-referrer-policy-missing", "Referrer Policy is not explicitly set",
                Severity.Low, "Referrer-Policy was not present.",
                "Navigation details may be disclosed to other origins according to browser defaults.",
                "Set a deliberate Referrer-Policy such as strict-origin-when-cross-origin or a stricter policy suitable for the application."));
        }

        if (Header(response, "Permissions-Policy") is null)
        {
            findings.Add(HeaderFinding(
                scanId, target, detectedAt, "header-permissions-policy-missing", "Permissions Policy is not explicitly set",
                Severity.Informational, "Permissions-Policy was not present.",
                "Browser features are not restricted by an application-defined policy.",
                "Define a Permissions-Policy that disables unneeded browser capabilities and grants required capabilities only to trusted origins."));
        }

        var allowOrigin = Header(response, "Access-Control-Allow-Origin");
        if (allowOrigin == "*")
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "cors-wildcard-origin", "CORS allows every origin",
                "Cross-Origin Resource Sharing", Severity.Low, Confidence.High,
                "Access-Control-Allow-Origin is set to * on the assessed response.",
                "Any website may read this unauthenticated response. The actual risk depends on whether the response contains sensitive data.",
                "Allow only required trusted origins on sensitive endpoints and vary caches by Origin when responses differ by requester.",
                OwaspHeadersReference));
        }

        if (Header(response, "X-Powered-By") is not null || Header(response, "Server") is not null)
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "header-technology-disclosure", "Technology details are exposed in response headers",
                "Information Disclosure", Severity.Informational, Confidence.High,
                "The response contains Server or X-Powered-By technology-identification headers. Header values were not retained.",
                "Version and platform hints can help an attacker prioritize technology-specific research.",
                "Remove unnecessary technology-identification headers and keep all underlying components patched.",
                OwaspHeadersReference));
        }
    }

    private static void EvaluateCookies(
        HttpResponseMessage response,
        Uri target,
        Guid scanId,
        DateTimeOffset detectedAt,
        ICollection<Finding> findings)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            return;
        }

        var cookieHeaders = cookies.ToArray();
        var missingSecure = target.Scheme == Uri.UriSchemeHttps
            ? cookieHeaders.Count(static value => !CookieSecureRegex().IsMatch(value))
            : 0;
        var missingHttpOnly = cookieHeaders.Count(static value => !CookieHttpOnlyRegex().IsMatch(value));
        var missingSameSite = cookieHeaders.Count(static value => !CookieSameSiteRegex().IsMatch(value));

        AddCookieFinding(findings, scanId, target, detectedAt, "cookie-secure-missing", "Cookies are missing the Secure attribute",
            Severity.Medium, missingSecure, "Cookies without Secure may be transmitted over an unencrypted connection.",
            "Add Secure to every cookie that should only travel over HTTPS.");
        AddCookieFinding(findings, scanId, target, detectedAt, "cookie-httponly-missing", "Cookies are missing the HttpOnly attribute",
            Severity.Low, missingHttpOnly, "Script-readable session cookies can increase the impact of cross-site scripting.",
            "Add HttpOnly to authentication and other cookies that do not require JavaScript access.");
        AddCookieFinding(findings, scanId, target, detectedAt, "cookie-samesite-missing", "Cookies are missing the SameSite attribute",
            Severity.Low, missingSameSite, "Cookies without an explicit SameSite policy may be included in unwanted cross-site requests.",
            "Set SameSite=Lax or Strict where possible. Use SameSite=None; Secure only where cross-site use is required.");
    }

    private static void EvaluateHtml(
        string html,
        Uri target,
        Guid scanId,
        DateTimeOffset detectedAt,
        ICollection<Finding> findings)
    {
        if (target.Scheme == Uri.UriSchemeHttps && MixedActiveContentRegex().IsMatch(html))
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "html-mixed-active-content", "HTTPS page references active content over HTTP",
                "Transport Security", Severity.High, Confidence.High,
                "At least one script, stylesheet, frame, or form action uses an explicit http:// URL. Content and URL values were not retained.",
                "Active mixed content can be modified in transit and may compromise the security of the HTTPS page.",
                "Serve every active resource over HTTPS and replace hard-coded HTTP URLs with verified HTTPS URLs.",
                OwaspTransportReference));
        }

        if (target.Scheme == Uri.UriSchemeHttps && MixedPassiveContentRegex().IsMatch(html))
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "html-mixed-passive-content", "HTTPS page references passive content over HTTP",
                "Transport Security", Severity.Low, Confidence.High,
                "At least one image, audio, or video resource uses an explicit http:// URL. Content and URL values were not retained.",
                "Passive mixed content can disclose browsing activity and may be modified in transit.",
                "Serve all media over HTTPS and update hard-coded HTTP resource URLs.",
                OwaspTransportReference));
        }

        var containsPassword = PasswordInputRegex().IsMatch(html);
        var insecureForm = InsecureFormActionRegex().IsMatch(html) ||
            (target.Scheme == Uri.UriSchemeHttp && containsPassword);
        if (insecureForm)
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "html-insecure-form", "Form data may be submitted without encryption",
                "Transport Security", Severity.High, Confidence.High,
                "A form explicitly submits to HTTP, or a password field is presented on an HTTP page. Form values were not collected.",
                "Submitted credentials or personal data may be intercepted or changed in transit.",
                "Serve the page over HTTPS and submit every sensitive form only to an HTTPS endpoint.",
                OwaspTransportReference));
        }

        var externalScriptsWithoutIntegrity = ExternalScriptRegex()
            .Matches(html)
            .Cast<Match>()
            .Count(match =>
                !IntegrityAttributeRegex().IsMatch(match.Value) &&
                Uri.TryCreate(match.Groups["url"].Value, UriKind.Absolute, out var scriptUrl) &&
                !IsSameOrigin(target, scriptUrl));
        if (externalScriptsWithoutIntegrity > 0)
        {
            findings.Add(CreateFinding(
                scanId, target, detectedAt, "html-external-script-no-sri", "External scripts lack integrity metadata",
                "Supply Chain", Severity.Low, Confidence.Medium,
                $"Found {externalScriptsWithoutIntegrity} external script tag(s) without an integrity attribute. Script URLs were not retained.",
                "If a third-party script host is compromised, modified JavaScript can execute in the application's origin.",
                "Use Subresource Integrity for stable third-party assets, pin versions, minimize third-party JavaScript, and maintain an explicit vendor-review process.",
                new Uri("https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity")));
        }
    }

    private static Finding HeaderFinding(
        Guid scanId,
        Uri target,
        DateTimeOffset detectedAt,
        string ruleId,
        string title,
        Severity severity,
        string evidence,
        string risk,
        string remediation) =>
        CreateFinding(scanId, target, detectedAt, ruleId, title, "Security Headers", severity, Confidence.High,
            evidence, risk, remediation, OwaspHeadersReference);

    private static void AddCookieFinding(
        ICollection<Finding> findings,
        Guid scanId,
        Uri target,
        DateTimeOffset detectedAt,
        string ruleId,
        string title,
        Severity severity,
        int affectedCount,
        string risk,
        string remediation)
    {
        if (affectedCount == 0)
        {
            return;
        }

        findings.Add(CreateFinding(
            scanId, target, detectedAt, ruleId, title, "Session Management", severity, Confidence.Medium,
            $"{affectedCount} Set-Cookie header(s) did not include the expected attribute. Cookie names and values were not retained.",
            risk, remediation, OwaspCookieReference));
    }

    private static Finding CreateFinding(
        Guid scanId,
        Uri target,
        DateTimeOffset detectedAt,
        string ruleId,
        string title,
        string category,
        Severity severity,
        Confidence confidence,
        string evidence,
        string risk,
        string remediation,
        Uri reference,
        string? testMethod = null) =>
        new(
            Id: Guid.NewGuid(),
            ScanId: scanId,
            RuleId: ruleId,
            Title: title,
            Category: category,
            Severity: severity,
            Confidence: confidence,
            AffectedUrl: RedactToOrigin(target),
            AffectedParameter: null,
            TestMethod: testMethod ?? DefaultTestMethod(ruleId),
            Evidence: evidence,
            RiskDescription: risk,
            Remediation: remediation,
            References: [reference],
            Status: FindingStatus.Open,
            FirstDetectedAt: detectedAt,
            LastDetectedAt: detectedAt);

    private static string DefaultTestMethod(string ruleId)
    {
        if (ruleId.StartsWith("header-", StringComparison.Ordinal) ||
            ruleId.StartsWith("cors-", StringComparison.Ordinal))
        {
            return "Sent one unauthenticated GET request without browser cookies or credentials and inspected only the returned HTTP response headers.";
        }

        if (ruleId.StartsWith("cookie-", StringComparison.Ordinal))
        {
            return "Sent one unauthenticated GET request and inspected Set-Cookie attribute names. Cookie names and values were not retained.";
        }

        if (ruleId.StartsWith("html-", StringComparison.Ordinal))
        {
            return "Sent one unauthenticated GET request, read at most 1 MB of public HTML, and checked structural patterns without executing page scripts or retaining page content.";
        }

        return "Sent one unauthenticated GET request without browser cookies or credentials and evaluated the public response without modifying application data.";
    }

    private static ScanSummary BuildSummary(
        IReadOnlyCollection<Finding> findings,
        int totalChecks,
        int requestsSent) =>
        new(
            TotalChecks: totalChecks,
            RequestsSent: requestsSent,
            TotalFindings: findings.Count,
            Critical: findings.Count(static finding => finding.Severity == Severity.Critical),
            High: findings.Count(static finding => finding.Severity == Severity.High),
            Medium: findings.Count(static finding => finding.Severity == Severity.Medium),
            Low: findings.Count(static finding => finding.Severity == Severity.Low),
            Informational: findings.Count(static finding => finding.Severity == Severity.Informational));

    private static int SeverityRank(Severity severity) => severity switch
    {
        Severity.Critical => 5,
        Severity.High => 4,
        Severity.Medium => 3,
        Severity.Low => 2,
        Severity.Informational => 1,
        _ => 0
    };

    private static string? Header(HttpResponseMessage response, string name)
    {
        if (response.Headers.TryGetValues(name, out var responseValues))
        {
            return string.Join(", ", responseValues);
        }

        return response.Content.Headers.TryGetValues(name, out var contentValues)
            ? string.Join(", ", contentValues)
            : null;
    }

    private static bool IsHtml(MediaTypeHeaderValue? contentType) =>
        contentType?.MediaType?.Contains("html", StringComparison.OrdinalIgnoreCase) == true;

    private static async Task<string> ReadLimitedBodyAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[16_384];

        while (output.Length < MaximumResponseBytes)
        {
            var remaining = MaximumResponseBytes - (int)output.Length;
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
        }

        return Encoding.UTF8.GetString(output.GetBuffer(), 0, (int)output.Length);
    }

    private static bool TryParseOrigin(string value, out Uri origin)
    {
        origin = null!;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var candidate) ||
            (candidate.Scheme != Uri.UriSchemeHttp && candidate.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(candidate.UserInfo) ||
            candidate.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(candidate.Query) ||
            !string.IsNullOrEmpty(candidate.Fragment))
        {
            return false;
        }

        origin = RedactToOrigin(candidate);
        return true;
    }

    private static async Task ValidateResolvedAddressesAsync(Uri target, CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(target.DnsSafeHost, cancellationToken);
        }
        catch (SocketException)
        {
            throw new ScanValidationException("The target hostname could not be resolved.");
        }

        if (addresses.Length == 0 || addresses.Any(address => IsDisallowedAddress(address, target.IsLoopback)))
        {
            throw new ScanValidationException("The target resolves to a private, link-local, multicast, or otherwise restricted network address.");
        }
    }

    private static bool IsDisallowedAddress(IPAddress address, bool allowLoopback)
    {
        if (IPAddress.IsLoopback(address))
        {
            return !allowLoopback;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] == 0 ||
                   bytes[0] == 10 ||
                   (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) ||
                   (bytes[0] == 169 && bytes[1] == 254) ||
                   (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   bytes[0] >= 224;
        }

        return address.Equals(IPAddress.IPv6Any) ||
               address.Equals(IPAddress.IPv6None) ||
               address.IsIPv6LinkLocal ||
               address.IsIPv6Multicast ||
               address.IsIPv6SiteLocal ||
               (bytes[0] & 0xfe) == 0xfc;
    }

    private static Uri RedactToOrigin(Uri value) => new(value.GetLeftPart(UriPartial.Authority) + "/");

    private static bool IsSameOrigin(Uri left, Uri right) =>
        Uri.Compare(left, right, UriComponents.SchemeAndServer, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0;

    private static bool IsRedirect(HttpStatusCode statusCode) => statusCode is
        HttpStatusCode.Moved or
        HttpStatusCode.Redirect or
        HttpStatusCode.RedirectMethod or
        HttpStatusCode.TemporaryRedirect or
        HttpStatusCode.PermanentRedirect;

    private sealed record TargetFetch(HttpResponseMessage Response, int RequestsSent);

    private sealed record ProbeResult(
        HttpStatusCode StatusCode,
        Uri? Location,
        string Body,
        string? AllowOrigin,
        string? AllowCredentials,
        string? AllowMethods);

    [GeneratedRegex(@"(?:^|;)\s*max-age\s*=\s*0(?:\s*;|$)", RegexOptions.IgnoreCase)]
    private static partial Regex HstsDisabledRegex();

    [GeneratedRegex(@"(?:^|;)\s*script-src[^;]*(?:'unsafe-inline'|'unsafe-eval')", RegexOptions.IgnoreCase)]
    private static partial Regex CspUnsafeScriptRegex();

    [GeneratedRegex(@"(?:^|;)\s*frame-ancestors\s+", RegexOptions.IgnoreCase)]
    private static partial Regex CspFrameAncestorsRegex();

    [GeneratedRegex(@"(?:^|;)\s*secure\s*(?:;|$)", RegexOptions.IgnoreCase)]
    private static partial Regex CookieSecureRegex();

    [GeneratedRegex(@"(?:^|;)\s*httponly\s*(?:;|$)", RegexOptions.IgnoreCase)]
    private static partial Regex CookieHttpOnlyRegex();

    [GeneratedRegex(@"(?:^|;)\s*samesite\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex CookieSameSiteRegex();

    [GeneratedRegex("""<(?:script|iframe|link|form)\b[^>]*(?:src|href|action)\s*=\s*['"]http://""", RegexOptions.IgnoreCase)]
    private static partial Regex MixedActiveContentRegex();

    [GeneratedRegex("""<(?:img|audio|video|source)\b[^>]*(?:src|srcset)\s*=\s*['"]http://""", RegexOptions.IgnoreCase)]
    private static partial Regex MixedPassiveContentRegex();

    [GeneratedRegex("""<input\b[^>]*type\s*=\s*['"]password['"]""", RegexOptions.IgnoreCase)]
    private static partial Regex PasswordInputRegex();

    [GeneratedRegex("""<form\b[^>]*action\s*=\s*['"]http://""", RegexOptions.IgnoreCase)]
    private static partial Regex InsecureFormActionRegex();

    [GeneratedRegex("""<script\b[^>]*src\s*=\s*['"](?<url>https?://[^'"]+)['"][^>]*>""", RegexOptions.IgnoreCase)]
    private static partial Regex ExternalScriptRegex();

    [GeneratedRegex(@"\bintegrity\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex IntegrityAttributeRegex();

    [GeneratedRegex(@"SQL syntax.*MySQL|mysql_(?:query|fetch)|MySqlException", RegexOptions.IgnoreCase)]
    private static partial Regex MySqlErrorRegex();

    [GeneratedRegex(@"PostgreSQL.*ERROR|Npgsql\.|org\.postgresql\.util\.PSQLException", RegexOptions.IgnoreCase)]
    private static partial Regex PostgreSqlErrorRegex();

    [GeneratedRegex(@"Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|SqlException", RegexOptions.IgnoreCase)]
    private static partial Regex SqlServerErrorRegex();

    [GeneratedRegex(@"ORA-\d{4,5}|OracleException", RegexOptions.IgnoreCase)]
    private static partial Regex OracleErrorRegex();

    [GeneratedRegex(@"SQLite(?:3)?::|SQLiteException|sqlite error", RegexOptions.IgnoreCase)]
    private static partial Regex SqliteErrorRegex();
}
