opera-proxy fork
===========

- Original author - [Snawoot](https://github.com/Snawoot)
- Fork based - [Alexey71](https://github.com/Alexey71)
- Some ideas - [SLY-F0X](https://github.com/SLY-F0X)

Standalone Opera VPN client.

Just run it and it'll start a plain HTTP proxy server forwarding traffic through "Opera VPN" proxies of your choice.
By default the application listens on 127.0.0.1:18080.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Uses TLS for secure communication with upstream proxies
* Zero configuration
* Simple and straightforward

## Installation

#### Binaries

Pre-built binaries are available [here](https://github.com/xteamlyer/opera-proxy/releases/latest).

#### Build from source

Alternatively, you may install opera-proxy from source. Run the following within the source directory:

```
make install
```

## Usage

List available countries:

```
$ ./opera-proxy -list-countries
country code,country name
EU,Europe
AS,Asia
AM,Americas
```

Run proxy via country of your choice:

```
$ ./opera-proxy -country EU
```

Also it is possible to export proxy addresses and credentials:

```
$ ./opera-proxy -country EU -list-proxies
Proxy login: ABCF206831D0BDC0C8C3AE5283F99EF6726444B3
Proxy password: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb3VudHJ5IjoidWEiLCJpYXQiOjE2MTY4MDkxMTIsImlkIjoic2UwMzE2LTYweGY3aTBxMGhoOWQ1MWF0emd0IiwiaXAiOiI3Ny4xMTEuMjQ3LjE3IiwidnBuX2xvZ2luIjoiSzJYdmJ5R0tUb3JLbkpOaDNtUGlGSTJvSytyVTA5bXMraGt2c2UwRWJBcz1Ac2UwMzE2LmJlc3QudnBuIn0.ZhqqzVyKmc3hZG6VVwWfn4nvVIPuZvaEfOLXfTppyvo
Proxy-Authorization: Basic QUJDRjIwNjgzMUQwQkRDMEM4QzNBRTUyODNGOTlFRjY3MjY0NDRCMzpleUpoYkdjaU9pSklVekkxTmlJc0luUjVjQ0k2SWtwWFZDSjkuZXlKamIzVnVkSEo1SWpvaWRXRWlMQ0pwWVhRaU9qRTJNVFk0TURreE1USXNJbWxrSWpvaWMyVXdNekUyTFRZd2VHWTNhVEJ4TUdob09XUTFNV0YwZW1kMElpd2lhWEFpT2lJM055NHhNVEV1TWpRM0xqRTNJaXdpZG5CdVgyeHZaMmx1SWpvaVN6SllkbUo1UjB0VWIzSkxia3BPYUROdFVHbEdTVEp2U3l0eVZUQTViWE1yYUd0MmMyVXdSV0pCY3oxQWMyVXdNekUyTG1KbGMzUXVkbkJ1SW4wLlpocXF6VnlLbWMzaFpHNlZWd1dmbjRudlZJUHVadmFFZk9MWGZUcHB5dm8=

host,ip_address,port
eu0.sec-tunnel.com,77.111.244.26,443
eu1.sec-tunnel.com,77.111.244.67,443
eu2.sec-tunnel.com,77.111.247.51,443
eu3.sec-tunnel.com,77.111.244.22,443
```

You can also skip the SurfEasy discover request and take endpoints from an existing CSV, while still using the normal server selection logic including `-server-selection fastest`:

```
$ ./opera-proxy -discover-csv proxies.csv -server-selection fastest
```

If direct SurfEasy API access is unstable, you can point discovery at a text file with fallback proxies. The app will read `proxies.txt`, test API proxies in parallel, and stop on the first one that successfully completes init/discover. File entries may be plain `host:port`, URL-style `http://user:pass@host:port`, or `host:port:user:pass` like `10proxies.txt`:

```
$ ./opera-proxy -api-proxy-file proxies.txt -country EU
```

By default it tests up to 5 candidates at once. You can change that with `-api-proxy-parallel`:

```
$ ./opera-proxy -api-proxy-file proxies.txt -api-proxy-parallel 5 -country EU
```

You can also download the proxy list from a URL. If the download fails, the app can fall back to a local file:

```
$ ./opera-proxy -api-proxy-list-url https://example.com/proxies.txt -country EU
```

```
$ ./opera-proxy -api-proxy-list-url https://example.com/proxies.txt -api-proxy-file proxies.txt -country EU
```

If you want selected destinations to go directly instead of through the Opera proxy, use `-proxy-bypass`. It accepts a comma-separated list of host or URL patterns and supports `*` in hostnames:

```
$ ./opera-proxy -country EU -proxy-bypass "api2.sec-tunnel.com,*.example.com,https://download.test.local/list.txt"
```

If `-proxy-bypass` is not passed, the app also tries to read `proxy-bypass.txt` from the current working directory. The file supports one pattern per line, comments via `#`, and comma-separated values on the same line.

If SurfEasy discover returns API error `801`, the app also automatically tries `proxies.csv` from the current working directory, even when `-discover-csv` was not passed.

## List of arguments

| Argument | Type | Description |
| -------- | ---- | ----------- |
| api-address | String | override IP address of api2.sec-tunnel.com |
| api-client-type | String | client type reported to SurfEasy API (default "se0316") |
| api-client-version | String | client version reported to SurfEasy API (default "Stable 114.0.5282.21") |
| api-login | String | SurfEasy API login (default "se0316") |
| api-password | String | SurfEasy API password (default "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II") |
| api-proxy | String | additional proxy server used to access SurfEasy API |
| api-proxy-file | String | path to text file with candidate proxy servers for SurfEasy API access, one per line; proxies are tried in order until init/discover succeeds |
| api-proxy-list-url | String | URL of a text file with candidate proxy servers for SurfEasy API access; falls back to `-api-proxy-file` if download fails |
| api-proxy-parallel | Number | number of API proxy candidates tested in parallel when `-api-proxy-file` is used (default 5) |
| api-user-agent | String | user agent reported to SurfEasy API (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0") |
| bind-address | String | proxy listen address (default "127.0.0.1:18080") |
| bootstrap-dns | String | Comma-separated list of DNS/DoH/DoT resolvers for initial discovery of SurfEasy API address. Supported schemes are: `dns://`, `https://`, `tls://`, `tcp://`. Examples: `https://1.1.1.1/dns-query`, `tls://9.9.9.9:853`  (default `https://1.1.1.3/dns-query,https://8.8.8.8/dns-query,https://dns.google/dns-query,https://security.cloudflare-dns.com/dns-query,https://fidelity.vm-0.com/q,https://wikimedia-dns.org/dns-query,https://dns.adguard-dns.com/dns-query,https://dns.quad9.net/dns-query,https://doh.cleanbrowsing.org/doh/adult-filter/`) |
| cafile | String | use custom CA certificate bundle file |
| config | String | read configuration from file with space-separated keys and values |
| country | String | desired proxy location (default "EU") |
| discover-csv | String | read proxy endpoints from CSV instead of SurfEasy discover API |
| dp-export | - | export configuration for dumbproxy |
| fake-SNI | String | domain name to use as SNI in outbound TLS and in tunneled TLS ClientHello when possible |
| init-retries | Number | number of attempts for initialization steps, zero for unlimited retry |
| init-retry-interval | Duration | delay between initialization retries (default 5s) |
| list-countries | - | list available countries and exit |
| list-proxies | - | output proxy list and exit |
| override-proxy-address | string | use fixed proxy address instead of server address returned by SurfEasy API |
| proxy-bypass | String | comma-separated list of destination host or URL patterns that should bypass proxying and connect directly; matching is case-insensitive and supports `*` in hostnames; if omitted, `proxy-bypass.txt` from the current working directory is loaded automatically when present |
| proxy-blacklist | String | path to file with blacklisted proxy addresses, one `host[:port]` per line |
| proxy | String | sets base proxy to use for all dial-outs. Format: `<http\|https\|socks5\|socks5h>://[login:password@]host[:port]` Examples: `http://user:password@192.168.1.1:3128`, `socks5://10.0.0.1:1080` |
| refresh | Duration | login refresh interval (default 4h0m0s) |
| refresh-retry | Duration | login refresh retry interval (default 5s) |
| server-selection | Enum | server selection policy (first/random/fastest) (default fastest) |
| server-selection-dl-limit | Number | restrict amount of downloaded data per connection by fastest server selection |
| server-selection-test-url | String | URL used for download benchmark by fastest server selection policy (default `https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js`) |
| server-selection-timeout | Duration | timeout given for server selection function to produce result (default 30s) |
| timeout | Duration | timeout for network operations (default 10s) |
| verbosity | Number | logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical) (default 20) |
| version | - | show program version and exit |
| socks-mode | - | listen for SOCKS requests instead of HTTP |

