using System.Text;
using System.Text.RegularExpressions;
using static DnsStamps.Helpers;

namespace DnsStamps
{
    public enum Protocol : byte
    {
        DNSCrypt = 0x01,
        DOH,
        DOT,
        Plain,
        ODOH,
        AnonymizedRelay = 0x81,
        ODOHRelay = 0x85
    }

    public class StampProperties
    {
        public bool DnsSec { get; set; } = true;
        public bool NoLog { get; set; } = true;
        public bool NoFilter { get; set; } = true;

        public byte ToByte()
        {
            return (byte)(
                (DnsSec ? 1 << 0 : 0) |
                (NoLog ? 1 << 1 : 0) |
                (NoFilter ? 1 << 2 : 0)
            );
        }
    }

    public interface IStamp
    {
        string ToString();
    }

    public class DnsCryptStamp : IStamp
    {
        public StampProperties Properties { get; } = new StampProperties();
        public string Address { get; }
        public string PublicKey { get; }
        public string ProviderName { get; }

        public DnsCryptStamp(string address, string publicKey, string providerName)
        {
            Address = address;
            PublicKey = SanitizeHex(publicKey);
            ProviderName = providerName;
        }

        public override string ToString()
        {
            var bytes = new List<byte> { (byte)Protocol.DNSCrypt, Properties.ToByte(), 0, 0, 0, 0, 0, 0, 0 };

            // Address
            var addrBytes = Encoding.UTF8.GetBytes(Address);
            bytes.Add((byte)addrBytes.Length);
            bytes.AddRange(addrBytes);

            // Public Key
            var pkBytes = HexToBytes(PublicKey);
            bytes.Add((byte)pkBytes.Length);
            bytes.AddRange(pkBytes);

            // Provider Name
            var providerBytes = Encoding.UTF8.GetBytes(ProviderName);
            bytes.Add((byte)providerBytes.Length);
            bytes.AddRange(providerBytes);

            return $"sdns://{UrlSafeBase64Encode(bytes.ToArray())}";
        }
    }

    public class ODoHStamp : IStamp
    {
        public StampProperties Properties { get; } = new StampProperties();
        public string HostName { get; }
        public string Path { get; }

        public ODoHStamp(string hostName, string path)
        {
            HostName = hostName;
            Path = path;
        }

        public virtual string ToString()
        {
            var bytes = new List<byte> { (byte)Protocol.ODOH, Properties.ToByte(), 0, 0, 0, 0, 0, 0, 0 };

            // HostName
            var hostBytes = Encoding.UTF8.GetBytes(HostName);
            bytes.Add((byte)hostBytes.Length);
            bytes.AddRange(hostBytes);

            // Path
            var pathBytes = Encoding.UTF8.GetBytes(Path);
            bytes.Add((byte)pathBytes.Length);
            bytes.AddRange(pathBytes);

            return $"sdns://{UrlSafeBase64Encode(bytes.ToArray())}";
        }
    }

    public class DoHStamp : ODoHStamp
    {
        public string Address { get; }
        public string Hash { get; }

        public DoHStamp(string address, string? hash, string hostName, string path)
            : base(hostName, path)
        {
            Address = address;
            Hash = SanitizeHex(hash);
        }

        public override string ToString()
        {
            return BuildStamp(Protocol.DOH);
        }

        protected string BuildStamp(Protocol protocol)
        {
            var bytes = new List<byte> { (byte)protocol, Properties.ToByte(), 0, 0, 0, 0, 0, 0, 0 };

            // Address
            var addrBytes = Encoding.UTF8.GetBytes(Address);
            bytes.Add((byte)addrBytes.Length);
            bytes.AddRange(addrBytes);

            // Hash
            var hashBytes = HexToBytes(Hash);
            bytes.Add((byte)hashBytes.Length);
            bytes.AddRange(hashBytes);

            // HostName
            var hostBytes = Encoding.UTF8.GetBytes(HostName);
            bytes.Add((byte)hostBytes.Length);
            bytes.AddRange(hostBytes);

            // Path
            var pathBytes = Encoding.UTF8.GetBytes(Path);
            bytes.Add((byte)pathBytes.Length);
            bytes.AddRange(pathBytes);

            return $"sdns://{UrlSafeBase64Encode(bytes.ToArray())}";
        }
    }

    public class ODoHRelayStamp : DoHStamp
    {
        public ODoHRelayStamp(string address, string? hash, string hostName, string path)
            : base(address, hash, hostName, path) { }

        public override string ToString()
        {
            return BuildStamp(Protocol.ODOHRelay);
        }
    }

    public class AnonymizedRelayStamp : IStamp
    {
        public string Address { get; }

        public AnonymizedRelayStamp(string address)
        {
            Address = address;
        }

        public override string ToString()
        {
            var bytes = new List<byte> { (byte)Protocol.AnonymizedRelay };
            var addrBytes = Encoding.UTF8.GetBytes(Address);
            bytes.Add((byte)addrBytes.Length);
            bytes.AddRange(addrBytes);
            return $"sdns://{UrlSafeBase64Encode(bytes.ToArray())}";
        }
    }

    public class DoTStamp : IStamp
    {
        public StampProperties Properties { get; } = new StampProperties();
        public string Address { get; }
        public string Hash { get; }
        public string HostName { get; }

        public DoTStamp(string address, string hash, string hostName)
        {
            Address = address;
            Hash = SanitizeHex(hash);
            HostName = hostName;
        }

        public override string ToString()
        {
            var bytes = new List<byte> { (byte)Protocol.DOT, Properties.ToByte(), 0, 0, 0, 0, 0, 0, 0 };

            // Address
            var addrBytes = Encoding.UTF8.GetBytes(Address);
            bytes.Add((byte)addrBytes.Length);
            bytes.AddRange(addrBytes);

            // Hash
            var hashBytes = HexToBytes(Hash);
            bytes.Add((byte)hashBytes.Length);
            bytes.AddRange(hashBytes);

            // HostName
            var hostBytes = Encoding.UTF8.GetBytes(HostName);
            bytes.Add((byte)hostBytes.Length);
            bytes.AddRange(hostBytes);

            return $"sdns://{UrlSafeBase64Encode(bytes.ToArray())}";
        }
    }

    public class PlainStamp : IStamp
    {
        public StampProperties Properties { get; } = new StampProperties();
        public string Address { get; }

        public PlainStamp(string address)
        {
            Address = address;
        }

        public override string ToString()
        {
            var bytes = new List<byte> { (byte)Protocol.Plain, Properties.ToByte(), 0, 0, 0, 0, 0, 0, 0 };

            // Address
            var addrBytes = Encoding.UTF8.GetBytes(Address);
            bytes.Add((byte)addrBytes.Length);
            bytes.AddRange(addrBytes);

            return $"sdns://{UrlSafeBase64Encode(bytes.ToArray())}";
        }
    }

    public static class StampParser
    {
        public static IStamp Parse(string stamp)
        {
            if (!stamp.StartsWith("sdns://"))
                throw new ArgumentException("Invalid scheme");

            var data = UrlSafeBase64Decode(stamp[7..]);

            if (data[0] == (byte)Protocol.AnonymizedRelay)
            {
                int addrLenA = data[1];
                var addressA = Encoding.UTF8.GetString(data, 2, addrLenA);
                return new AnonymizedRelayStamp(addressA);
            }

            var props = new StampProperties
            {
                DnsSec = (data[1] & (1 << 0)) != 0,
                NoLog = (data[1] & (1 << 1)) != 0,
                NoFilter = (data[1] & (1 << 2)) != 0
            };

            var index = 9;
            var addrLen = data[index++];
            var address = Encoding.UTF8.GetString(data, index, addrLen);
            index += addrLen;

            switch ((Protocol)data[0])
            {
                case Protocol.DNSCrypt:
                    int pkLen = data[index++];
                    var pk = BytesToHex(data, index, pkLen);
                    index += pkLen;
                    int providerLen = data[index++];
                    var provider = Encoding.UTF8.GetString(data, index, providerLen);
                    return new DnsCryptStamp(address, pk, provider)
                        {Properties = {DnsSec = props.DnsSec, NoFilter = props.NoFilter, NoLog = props.NoLog}};

                case Protocol.DOH:
                    int hashLen = data[index++];
                    var hash = BytesToHex(data, index, hashLen);
                    index += hashLen;
                    int hostLen = data[index++];
                    var host = Encoding.UTF8.GetString(data, index, hostLen);
                    index += hostLen;
                    int pathLen = data[index++];
                    var path = Encoding.UTF8.GetString(data, index, pathLen);
                    return new DoHStamp(address, hash, host, path)
                        { Properties = { DnsSec = props.DnsSec, NoFilter = props.NoFilter, NoLog = props.NoLog } };

                case Protocol.DOT:
                    int dotHashLen = data[index++];
                    var dotHash = BytesToHex(data, index, dotHashLen);
                    index += dotHashLen;
                    int dotHostLen = data[index++];
                    var dotHost = Encoding.UTF8.GetString(data, index, dotHostLen);
                    return new DoTStamp(address, dotHash, dotHost)
                        { Properties = { DnsSec = props.DnsSec, NoFilter = props.NoFilter, NoLog = props.NoLog } };

                case Protocol.ODOH:
                    int pathLenO = data[index++];
                    var pathO = Encoding.UTF8.GetString(data, index, pathLenO);
                    return new ODoHStamp(address, pathO)
                        { Properties = { DnsSec = props.DnsSec, NoFilter = props.NoFilter, NoLog = props.NoLog } };

                case Protocol.ODOHRelay:
                    int relayHashLen = data[index++];
                    var relayHash = BytesToHex(data, index, relayHashLen);
                    index += relayHashLen;
                    int relayHostLen = data[index++];
                    var relayHost = Encoding.UTF8.GetString(data, index, relayHostLen);
                    index += relayHostLen;
                    int relayPathLen = data[index++];
                    var relayPath = Encoding.UTF8.GetString(data, index, relayPathLen);
                    return new ODoHRelayStamp(address, relayHash, relayHost, relayPath)
                        { Properties = { DnsSec = props.DnsSec, NoFilter = props.NoFilter, NoLog = props.NoLog } };

                case Protocol.Plain:
                    return new PlainStamp(address)
                        { Properties = { DnsSec = props.DnsSec, NoFilter = props.NoFilter, NoLog = props.NoLog } };

            }

            throw new NotSupportedException($"Unsupported protocol: {data[0]}");
        }

        public static StampProperties ParseProps(string stamp)
        {
            if (!stamp.StartsWith("sdns://"))
                throw new ArgumentException("Invalid scheme");

            var data = UrlSafeBase64Decode(stamp[7..]);

            return new StampProperties
            {
                DnsSec = (data[1] & (1 << 0)) != 0,
                NoLog = (data[1] & (1 << 1)) != 0,
                NoFilter = (data[1] & (1 << 2)) != 0
            };
        }
    }
    
    internal static class Helpers
    {
        public static string SanitizeHex(string input)
        {
            try
            {
                return Regex.Replace(input, @"[^0-9a-fA-F]", "");
            }
            catch (Exception e)
            {
                return input;
            }
        }

        public static byte[] HexToBytes(string hex)
        {
            hex = SanitizeHex(hex);
            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string BytesToHex(byte[] data, int offset, int length)
        {
            var sb = new StringBuilder();
            for (var i = offset; i < offset + length; i++)
                sb.Append(data[i].ToString("x2"));
            return sb.ToString();
        }

        public static string UrlSafeBase64Encode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        public static byte[] UrlSafeBase64Decode(string input)
        {
            var base64 = input
                .Replace('-', '+')
                .Replace('_', '/');

            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }
    }
}