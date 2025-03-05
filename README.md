# DnsStamps.Net

```csharp
using DnsStamps;

var dnscrypt = new DNSCryptStamp(
    "[2600:1406:3a00:21::173e:2e66]:443",
    "0338ad6e03b98fd5bf2828e2abfbf2c2fa74cf408834f9b6a343fbe2b4c0705a",
    "example.com"
);
Console.WriteLine(dnscrypt.ToString());

Console.WriteLine(new DnsStamps.DOHStamp(address: "8.8.8.8", hash: "", hostName: "dns.google", path: "/dns-query")
    {Properties = {DnsSec = true, NoFilter = false, NoLog = false}}.ToString());
```

Refer to the great implementation of [**rs/node-dnsstamp**](https://github.com/rs/node-dnsstamp)

