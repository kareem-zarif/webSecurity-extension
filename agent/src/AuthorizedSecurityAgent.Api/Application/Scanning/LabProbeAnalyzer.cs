using System.Text.RegularExpressions;

namespace AuthorizedSecurityAgent.Application.Scanning;

internal static partial class LabProbeAnalyzer
{
    internal static bool HasRawReflection(string body, string canary) =>
        body.Contains(canary, StringComparison.Ordinal);

    internal static bool ContainsMarker(string body, string marker) =>
        marker.Length > 0 && body.Contains(marker, StringComparison.Ordinal);

    internal static bool IndicatesBooleanSqlInjection(
        LabResponseSnapshot baseline,
        LabResponseSnapshot trueProbe,
        LabResponseSnapshot falseProbe)
    {
        if (!baseline.IsSuccess || !trueProbe.IsSuccess || !falseProbe.IsSuccess ||
            trueProbe.Body.Length == 0 ||
            string.Equals(trueProbe.Body, falseProbe.Body, StringComparison.Ordinal))
        {
            return false;
        }

        if (string.Equals(baseline.Body, trueProbe.Body, StringComparison.Ordinal) &&
            !string.Equals(baseline.Body, falseProbe.Body, StringComparison.Ordinal))
        {
            return true;
        }

        var trueDistance = Math.Abs(baseline.Body.Length - trueProbe.Body.Length);
        var falseDistance = Math.Abs(baseline.Body.Length - falseProbe.Body.Length);
        return falseDistance >= trueDistance + Math.Max(20, baseline.Body.Length / 5);
    }

    internal static bool IndicatesIdor(
        LabResponseSnapshot accountAOwn,
        LabResponseSnapshot accountACrossAccount,
        LabResponseSnapshot accountBOwn) =>
        accountAOwn.IsSuccess &&
        accountACrossAccount.IsSuccess &&
        accountBOwn.IsSuccess &&
        accountACrossAccount.Body.Length > 0 &&
        string.Equals(accountACrossAccount.Body, accountBOwn.Body, StringComparison.Ordinal) &&
        !string.Equals(accountAOwn.Body, accountBOwn.Body, StringComparison.Ordinal);

    internal static bool IndicatesActiveUpload(LabResponseSnapshot retrieval, string marker) =>
        retrieval.IsSuccess &&
        retrieval.ContentType?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true &&
        ContainsMarker(retrieval.Body, marker);

    internal static string? DetectSqlErrorFamily(string body)
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

internal sealed record LabResponseSnapshot(
    int StatusCode,
    string Body,
    string? ContentType = null)
{
    public bool IsSuccess => StatusCode is >= 200 and < 300;
}
