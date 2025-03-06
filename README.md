# DnsStamps.Net

[Nuget](https://www.nuget.org/packages/DnsStamps).Net

```csharp
using DnsStamps;

var dnscrypt = new DnsCryptStamp(
    "[2600:1406:3a00:21::173e:2e66]:443",
    "0338ad6e03b98fd5bf2828e2abfbf2c2fa74cf408834f9b6a343fbe2b4c0705a",
    "example.com"
);
Console.WriteLine(dnscrypt.ToString());

Console.WriteLine(new DnsStamps.DoHStamp(address: "8.8.8.8", hash: "", hostName: "dns.google", path: "/dns-query")
    {Properties = {DnsSec = true, NoFilter = false, NoLog = false}}.ToString());

if (StampParser.Parse("sdns://AgMAAAAAAAAADDk0LjE0MC4xNS4xNSCaOjT3J965vKUQA9nOnDn48n3ZxSQpAcK6saROY1oCGQw5NC4xNDAuMTUuMTUKL2Rucy1xdWVyeQ")
    is DoHStamp dohStamp)
{
    Console.WriteLine(dohStamp.Address);
    Console.WriteLine(dohStamp.Path);
}
```

Refer to the great implementation of [**rs/node-dnsstamp**](https://github.com/rs/node-dnsstamp)

