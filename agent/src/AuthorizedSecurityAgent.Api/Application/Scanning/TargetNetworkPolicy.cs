using System.Net;
using System.Net.Sockets;

namespace AuthorizedSecurityAgent.Application.Scanning;

internal static class TargetNetworkPolicy
{
    public static async Task ValidateAsync(
        Uri target,
        bool requirePrivateLab,
        CancellationToken cancellationToken)
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

        if (addresses.Length == 0)
        {
            throw new ScanValidationException("The target hostname did not resolve to an address.");
        }

        if (requirePrivateLab)
        {
            if (addresses.Any(static address => !IsPrivateLabAddress(address)))
            {
                throw new ScanValidationException("Lab exploitation mode refuses public targets. Use only localhost or an RFC1918/unique-local Docker lab address.");
            }

            return;
        }

        if (addresses.Any(address => IsRestrictedPublicAssessmentAddress(address, target.IsLoopback)))
        {
            throw new ScanValidationException("The target resolves to a private, link-local, multicast, or otherwise restricted network address.");
        }
    }

    internal static bool IsPrivateLabAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168);
        }

        return !address.Equals(IPAddress.IPv6Any) &&
               !address.Equals(IPAddress.IPv6None) &&
               !address.IsIPv6LinkLocal &&
               !address.IsIPv6Multicast &&
               !address.IsIPv6SiteLocal &&
               (bytes[0] & 0xfe) == 0xfc;
    }

    private static bool IsRestrictedPublicAssessmentAddress(IPAddress address, bool allowLoopback)
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
}
