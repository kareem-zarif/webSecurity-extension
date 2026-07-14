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

        using var response = await GetTargetAsync(target, cancellationToken);
        var assessedUrl = response.RequestMessage?.RequestUri ?? target;
        var detectedAt = DateTimeOffset.UtcNow;

        EvaluateTransport(assessedUrl, scanId, detectedAt, findings);
        EvaluateHeaders(response, assessedUrl, scanId, detectedAt, findings);
        EvaluateCookies(response, assessedUrl, scanId, detectedAt, findings);

        if (IsHtml(response.Content.Headers.ContentType))
        {
            var html = await ReadLimitedBodyAsync(response.Content, cancellationToken);
            EvaluateHtml(html, assessedUrl, scanId, detectedAt, findings);
        }

        findings.Sort(static (left, right) => SeverityRank(right.Severity).CompareTo(SeverityRank(left.Severity)));
        var completedAt = DateTimeOffset.UtcNow;

        return new ScanReport(
            ScanId: scanId,
            TargetUrl: RedactToOrigin(assessedUrl),
            StartedAt: startedAt,
            CompletedAt: completedAt,
            Summary: BuildSummary(findings),
            ChecksPerformed: ChecksPerformed,
            Findings: findings,
            ScopeNote: "Unauthenticated, non-destructive assessment of one explicitly authorized origin. No credentials, browser cookies, payload exploitation, brute force, persistence, or denial-of-service techniques were used.");
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

    private async Task<HttpResponseMessage> GetTargetAsync(Uri target, CancellationToken cancellationToken)
    {
        var current = target;

        for (var redirectCount = 0; redirectCount <= MaximumRedirects; redirectCount++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml", 0.9));

            var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if (!IsRedirect(response.StatusCode) || response.Headers.Location is null)
            {
                return response;
            }

            var redirect = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(current, response.Headers.Location);

            if (!IsSameOrigin(target, redirect))
            {
                return response;
            }

            response.Dispose();
            current = redirect;
        }

        throw new ScanValidationException("The target exceeded the safe redirect limit.");
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
        Uri reference) =>
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
            Evidence: evidence,
            RiskDescription: risk,
            Remediation: remediation,
            References: [reference],
            Status: FindingStatus.Open,
            FirstDetectedAt: detectedAt,
            LastDetectedAt: detectedAt);

    private static ScanSummary BuildSummary(IReadOnlyCollection<Finding> findings) =>
        new(
            TotalChecks: ChecksPerformed.Count,
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
}
