package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/xteamlyer/opera-proxy/clock"
	"github.com/xteamlyer/opera-proxy/dialer"
	"github.com/xteamlyer/opera-proxy/handler"
	clog "github.com/xteamlyer/opera-proxy/log"
	"github.com/xteamlyer/opera-proxy/resolver"
	se "github.com/xteamlyer/opera-proxy/seclient"

	_ "golang.org/x/crypto/x509roots/fallback"
	"golang.org/x/crypto/x509roots/fallback/bundle"
)

const (
	API_DOMAIN                 = "api2.sec-tunnel.com"
	PROXY_SUFFIX               = "sec-tunnel.com"
	DefaultDiscoverCSVFallback = "proxies.csv"
	DefaultProxyBypassFallback = "proxy-bypass.txt"

	// Default timeouts increased to reduce premature API errors on slow networks.
	DEFAULT_TIMEOUT                  = 30 * time.Second
	DEFAULT_SERVER_SELECTION_TIMEOUT = 60 * time.Second

	// Reduced idle connection pool to lower resource usage on embedded/low-RAM hosts.
	HTTP_MAX_IDLE_CONNS          = 10
	HTTP_MAX_IDLE_CONNS_PER_HOST = 3
	HTTP_IDLE_CONN_TIMEOUT       = 60 * time.Second

	// SE_* constants apply to the SurfEasy API transport and the speed-probe transport.
	// They allow more concurrent connections than the proxy handler transport because
	// API calls are short-lived and few (dozens, not thousands).
	SE_MAX_IDLE_CONNS          = 100
	SE_IDLE_CONN_TIMEOUT       = 90 * time.Second
	SE_TLS_HANDSHAKE_TIMEOUT   = 10 * time.Second
	SE_EXPECT_CONTINUE_TIMEOUT = 1 * time.Second

	// BENCH_WORKERS is the maximum number of concurrent speed-probe goroutines.
	BENCH_WORKERS = 8
)

func perror(msg string) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, msg)
}

func arg_fail(msg string) {
	perror(msg)
	perror("Usage:")
	flag.PrintDefaults()
	os.Exit(2)
}

type CSVArg struct {
	values []string
}

func (a *CSVArg) String() string {
	if len(a.values) == 0 {
		return ""
	}
	buf := new(bytes.Buffer)
	wr := csv.NewWriter(buf)
	wr.Write(a.values)
	wr.Flush()
	return strings.TrimRight(buf.String(), "\n")
}

func (a *CSVArg) Set(line string) error {
	rd := csv.NewReader(strings.NewReader(line))
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	values, err := rd.Read()
	if err == io.EOF {
		a.values = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to parse comma-separated argument: %w", err)
	}
	a.values = values
	return nil
}

type serverSelectionArg struct {
	value dialer.ServerSelection
}

func (a *serverSelectionArg) Set(s string) error {
	v, err := dialer.ParseServerSelection(s)
	if err != nil {
		return err
	}
	a.value = v
	return nil
}

func (a *serverSelectionArg) String() string {
	return a.value.String()
}

type CLIArgs struct {
	country                string
	countryExplicit        bool
	discoverCSV            string
	listCountries          bool
	listProxies            bool
	listProxiesAll         bool
	listProxiesAllOut      string
	fetchFreeProxyOut      string
	fetchFreeProxyURL      string
	estimateProxySpeed     bool
	sortProxiesBy          string
	dpExport               bool
	discoverRepeat         int
	bindAddress            string
	socksMode              bool
	verbosity              int
	timeout                time.Duration
	showVersion            bool
	proxy                  string
	apiLogin               string
	apiPassword            string
	apiAddress             string
	apiClientType          string
	apiClientVersion       string
	apiUserAgent           string
	apiProxy               string
	apiProxyFile           string
	apiProxyListURL        string
	apiProxyParallel       int
	bootstrapDNS           *CSVArg
	refresh                time.Duration
	refreshRetry           time.Duration
	initRetries            int
	initRetryInterval      time.Duration
	caFile                 string
	fakeSNI                string
	proxyBypass            *CSVArg
	proxyBlacklistFile     string
	proxyBlacklist         map[string]struct{}
	overrideProxyAddress   string
	proxySpeedTestURL      string
	proxySpeedTimeout      time.Duration
	proxySpeedDLLimit      int64
	serverSelection        serverSelectionArg
	serverSelectionTimeout time.Duration
	serverSelectionTestURL string
	serverSelectionDLLimit int64
}

func parse_args() *CLIArgs {
	args := &CLIArgs{
		bootstrapDNS: &CSVArg{
			values: []string{
				"https://1.1.1.3/dns-query",
				"https://8.8.8.8/dns-query",
				"https://dns.google/dns-query",
				"https://security.cloudflare-dns.com/dns-query",
				"https://fidelity.vm-0.com/q",
				"https://wikimedia-dns.org/dns-query",
				"https://dns.adguard-dns.com/dns-query",
				"https://dns.quad9.net/dns-query",
				"https://doh.cleanbrowsing.org/doh/adult-filter/",
			},
		},
		proxyBypass:     &CSVArg{},
		serverSelection: serverSelectionArg{dialer.ServerSelectionFastest},
	}
	flag.StringVar(&args.country, "country", "EU", "desired proxy location; for list-proxies-all modes supports comma-separated codes or ALL")
	flag.StringVar(&args.discoverCSV, "discover-csv", "", "read proxy endpoints from CSV instead of SurfEasy discover API")
	flag.BoolVar(&args.listCountries, "list-countries", false, "list available countries and exit")
	flag.BoolVar(&args.listProxies, "list-proxies", false, "output proxy list and exit")
	flag.BoolVar(&args.listProxiesAll, "list-proxies-all", false, "output proxy list for all countries and exit")
	flag.StringVar(&args.listProxiesAllOut, "list-proxies-all-out", "", "write proxy list CSV to file")
	flag.StringVar(&args.fetchFreeProxyOut, "fetch-freeproxy-out", "", "download proxy list from advanced.name/freeproxy and save it as a text file with one ip:port per line")
	flag.StringVar(&args.fetchFreeProxyURL, "fetch-freeproxy-url", "https://advanced.name/freeproxy", "source URL for -fetch-freeproxy-out")
	flag.BoolVar(&args.estimateProxySpeed, "estimate-proxy-speed", false, "measure proxy response time for proxy list output")
	flag.StringVar(&args.sortProxiesBy, "sort-proxies-by", "speed", "proxy list sort order: speed, country, ip")
	flag.BoolVar(&args.dpExport, "dp-export", false, "export configuration for dumbproxy")
	flag.IntVar(&args.discoverRepeat, "discover-repeat", 1, "number of repeated discover requests to aggregate and deduplicate")
	flag.StringVar(&args.bindAddress, "bind-address", "127.0.0.1:18080", "proxy listen address")
	flag.BoolVar(&args.socksMode, "socks-mode", false, "listen for SOCKS requests instead of HTTP")
	flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical, 60 - silent/no output at all)")
	flag.DurationVar(&args.timeout, "timeout", DEFAULT_TIMEOUT,
		"timeout for network operations")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.StringVar(&args.proxy, "proxy", "", "sets base proxy to use for all dial-outs. "+
		"Format: <http|https|socks5|socks5h>://[login:password@]host[:port] "+
		"Examples: http://user:password@192.168.1.1:3128, socks5://10.0.0.1:1080")
	flag.Var(args.proxyBypass, "proxy-bypass", "comma-separated list of destination host or URL patterns that should bypass proxying and connect directly; matching is case-insensitive and supports * in hostnames")
	flag.StringVar(&args.apiClientVersion, "api-client-version", se.DefaultSESettings.ClientVersion, "client version reported to SurfEasy API")
	flag.StringVar(&args.apiClientType, "api-client-type", se.DefaultSESettings.ClientType, "client type reported to SurfEasy API")
	flag.StringVar(&args.apiUserAgent, "api-user-agent", se.DefaultSESettings.UserAgent, "user agent reported to SurfEasy API")
	flag.StringVar(&args.apiLogin, "api-login", "se0316", "SurfEasy API login")
	flag.StringVar(&args.apiPassword, "api-password", "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II", "SurfEasy API password")
	flag.StringVar(&args.apiAddress, "api-address", "", fmt.Sprintf("override IP address of %s", API_DOMAIN))
	flag.StringVar(&args.apiProxy, "api-proxy", "", "additional proxy server used to access SurfEasy API")
	flag.StringVar(&args.apiProxyFile, "api-proxy-file", "", "path to text file with candidate proxy servers for SurfEasy API access, one per line; proxies are tried in order until init/discover succeeds")
	flag.StringVar(&args.apiProxyListURL, "api-proxy-list-url", "", "URL of a text file with candidate proxy servers for SurfEasy API access; falls back to -api-proxy-file if download fails")
	flag.IntVar(&args.apiProxyParallel, "api-proxy-parallel", 15, "number of API proxy candidates tested in parallel when -api-proxy-file is used")
	flag.Var(args.bootstrapDNS, "bootstrap-dns",
		"comma-separated list of DNS/DoH/DoT resolvers for initial discovery of SurfEasy API address. "+
			"Supported schemes are: dns://, https://, tls://, tcp://. "+
			"Examples: https://1.1.1.1/dns-query,tls://9.9.9.9:853")
	flag.DurationVar(&args.refresh, "refresh", 4*time.Hour, "login refresh interval")
	flag.DurationVar(&args.refreshRetry, "refresh-retry", 5*time.Second, "login refresh retry interval")
	flag.IntVar(&args.initRetries, "init-retries", 0, "number of attempts for initialization steps, zero for unlimited retry")
	flag.DurationVar(&args.initRetryInterval, "init-retry-interval", 5*time.Second, "delay between initialization retries")
	flag.StringVar(&args.caFile, "cafile", "", "use custom CA certificate bundle file")
	flag.StringVar(&args.fakeSNI, "fake-SNI", "", "domain name to use as SNI in outbound TLS and tunneled TLS ClientHello where possible")
	flag.StringVar(&args.proxyBlacklistFile, "proxy-blacklist", "", "path to file with blacklisted proxy addresses, one host[:port] per line")
	flag.StringVar(&args.overrideProxyAddress, "override-proxy-address", "", "use fixed proxy address instead of server address returned by SurfEasy API")
	flag.StringVar(&args.proxySpeedTestURL, "proxy-speed-test-url", "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
		"URL used to measure proxy response time")
	flag.DurationVar(&args.proxySpeedTimeout, "proxy-speed-timeout", 15*time.Second, "timeout for a single proxy speed measurement")
	flag.Int64Var(&args.proxySpeedDLLimit, "proxy-speed-dl-limit", 262144, "limit of downloaded bytes for proxy speed measurement")
	flag.Var(&args.serverSelection, "server-selection", "server selection policy (first/random/fastest)")
	flag.DurationVar(&args.serverSelectionTimeout, "server-selection-timeout", DEFAULT_SERVER_SELECTION_TIMEOUT,
		"timeout given for server selection function to produce result")
	flag.StringVar(&args.serverSelectionTestURL, "server-selection-test-url",
		"https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
		"URL used for download benchmark by fastest server selection policy")
	flag.Int64Var(&args.serverSelectionDLLimit, "server-selection-dl-limit", 0,
		"restrict amount of downloaded data per connection by fastest server selection")
	flag.Func("config", "read configuration from file with space-separated keys and values", readConfig)
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "country" {
			args.countryExplicit = true
		}
	})
	if args.country == "" {
		arg_fail("Country can't be empty string.")
	}
	if args.discoverRepeat < 1 {
		arg_fail("discover-repeat must be >= 1.")
	}
	if args.apiProxyParallel < 1 {
		arg_fail("api-proxy-parallel must be >= 1.")
	}
	switch args.sortProxiesBy {
	case "speed", "country", "ip":
	default:
		arg_fail("sort-proxies-by must be one of: speed, country, ip.")
	}
	if args.listProxiesAllOut != "" {
		args.listProxiesAll = true
	}
	if args.listProxiesAll {
		args.estimateProxySpeed = true
	}
	if args.listCountries && args.listProxies ||
		args.listCountries && args.listProxiesAll ||
		args.listCountries && args.dpExport ||
		args.listCountries && args.fetchFreeProxyOut != "" ||
		args.listProxies && args.listProxiesAll ||
		args.listProxies && args.dpExport ||
		args.listProxies && args.fetchFreeProxyOut != "" ||
		args.listProxiesAll && args.dpExport ||
		args.listProxiesAll && args.fetchFreeProxyOut != "" ||
		args.dpExport && args.fetchFreeProxyOut != "" {
		arg_fail("mutually exclusive output arguments were provided")
	}
	return args
}

func proxyFromURLWrapper(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	cdialer, ok := next.(dialer.ContextDialer)
	if !ok {
		return nil, errors.New("only context dialers are accepted")
	}

	return dialer.ProxyDialerFromURL(u, cdialer)
}

// buildAPITransport returns an http.Transport tuned for infrequent API calls:
// reduced idle pool (saves goroutines/sockets), no forced HTTP/2.
func buildAPITransport(
	dialCtx func(context.Context, string, string) (net.Conn, error),
	dialTLSCtx func(context.Context, string, string) (net.Conn, error),
) *http.Transport {
	return &http.Transport{
		DialContext:           dialCtx,
		DialTLSContext:        dialTLSCtx,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          HTTP_MAX_IDLE_CONNS,
		MaxIdleConnsPerHost:   HTTP_MAX_IDLE_CONNS_PER_HOST,
		IdleConnTimeout:       HTTP_IDLE_CONN_TIMEOUT,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// buildSETransport returns an *http.Transport configured for SurfEasy API calls
// and speed probes. All SE transports share the same constants (SE_MAX_IDLE_CONNS,
// SE_IDLE_CONN_TIMEOUT, etc.) so there is a single definition instead of four.
//
// dialCtx is mandatory. dialTLSCtx is optional: pass nil to use Go's default TLS
// dialer (standard certificate verification). The caller may overwrite individual
// fields (e.g. TLSClientConfig) after calling buildSETransport.
func buildSETransport(
	dialCtx func(context.Context, string, string) (net.Conn, error),
	dialTLSCtx func(context.Context, string, string) (net.Conn, error),
) *http.Transport {
	return &http.Transport{
		DialContext:           dialCtx,
		DialTLSContext:        dialTLSCtx,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          SE_MAX_IDLE_CONNS,
		IdleConnTimeout:       SE_IDLE_CONN_TIMEOUT,
		TLSHandshakeTimeout:   SE_TLS_HANDSHAKE_TIMEOUT,
		ExpectContinueTimeout: SE_EXPECT_CONTINUE_TIMEOUT,
	}
}

// buildCAPool constructs the x509 cert pool used for all TLS verification.
// When -cafile is given, only that file is loaded (useful for custom/corporate CAs).
// Otherwise the bundled Mozilla NSS root store is used, which includes all
// major roots and supports AddCertWithConstraint for name-constrained CAs —
// strictly better than a plain PEM file.
func buildCAPool(caFile string, logger *clog.CondLogger) (*x509.CertPool, int) {
	pool := x509.NewCertPool()
	if caFile != "" {
		certs, err := os.ReadFile(caFile)
		if err != nil {
			logger.Error("Can't load CA file: %v", err)
			return nil, 15
		}
		if ok := pool.AppendCertsFromPEM(certs); !ok {
			logger.Error("Can't load certificates from CA file")
			return nil, 15
		}
		return pool, 0
	}
	for c := range bundle.Roots() {
		cert, err := x509.ParseCertificate(c.Certificate)
		if err != nil {
			logger.Error("Unable to parse bundled certificate: %v", err)
			return nil, 15
		}
		if c.Constraint == nil {
			pool.AddCert(cert)
		} else {
			pool.AddCertWithConstraint(cert, c.Constraint)
		}
	}
	return pool, 0
}

func normalizeAPIProxy(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.Contains(raw, "://") {
		return raw, nil
	}
	if strings.Contains(raw, "@") {
		return "http://" + raw, nil
	}

	parts := strings.Split(raw, ":")
	if len(parts) == 4 {
		host := strings.TrimSpace(parts[0])
		port := strings.TrimSpace(parts[1])
		user := strings.TrimSpace(parts[2])
		password := strings.TrimSpace(parts[3])
		if host == "" || port == "" || user == "" {
			return "", fmt.Errorf("invalid proxy entry %q", raw)
		}
		proxyURL := &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(host, port),
			User:   url.UserPassword(user, password),
		}
		return proxyURL.String(), nil
	}

	if len(parts) == 2 {
		host := strings.TrimSpace(parts[0])
		port := strings.TrimSpace(parts[1])
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid proxy entry %q", raw)
		}
		return "http://" + net.JoinHostPort(host, port), nil
	}

	return "", fmt.Errorf("unsupported proxy entry format %q", raw)
}

// stripComment strips an inline # comment from a config-file line and
// trims surrounding whitespace. Returns an empty string for blank/comment-only lines.
func stripComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func loadAPIProxyListFromReader(r io.Reader, source string) ([]string, error) {
	scanner := bufio.NewScanner(r)
	proxies := make([]string, 0)
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxy, err := normalizeAPIProxy(line)
		if err != nil {
			return nil, fmt.Errorf("invalid API proxy entry %q from %s: %w", line, source, err)
		}
		if _, ok := seen[proxy]; ok {
			continue
		}
		seen[proxy] = struct{}{}
		proxies = append(proxies, proxy)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read API proxy list from %s: %w", source, err)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no API proxies found in %s", source)
	}
	return proxies, nil
}

func loadAPIProxyList(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open API proxy list %q: %w", filename, err)
	}
	defer f.Close()
	return loadAPIProxyListFromReader(f, fmt.Sprintf("file %q", filename))
}

func loadProxyBypassList(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	seen := make(map[string]struct{})
	patterns := make([]string, 0)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		if line == "" {
			continue
		}

		var parsed CSVArg
		if err := parsed.Set(line); err != nil {
			return nil, fmt.Errorf("unable to parse proxy bypass entry %q from %s: %w", line, filename, err)
		}
		for _, value := range parsed.values {
			pattern := strings.TrimSpace(value)
			if pattern == "" {
				continue
			}
			if _, ok := seen[pattern]; ok {
				continue
			}
			seen[pattern] = struct{}{}
			patterns = append(patterns, pattern)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read proxy bypass list %q: %w", filename, err)
	}
	return patterns, nil
}

func loadAPIProxyListFromURL(listURL string, transport http.RoundTripper, timeout time.Duration) ([]string, error) {
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	req, err := http.NewRequest(http.MethodGet, listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request for API proxy list URL %q: %w", listURL, err)
	}
	req.Header.Set("User-Agent", "opera-proxy api-proxy-list fetcher/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to download API proxy list from %q: %w", listURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to download API proxy list from %q: unexpected HTTP status %s", listURL, resp.Status)
	}
	return loadAPIProxyListFromReader(resp.Body, fmt.Sprintf("URL %q", listURL))
}

func newSEClient(args *CLIArgs, baseDialer dialer.ContextDialer, caPool *x509.CertPool, apiProxy string) (*se.SEClient, error) {
	seclientDialer := baseDialer
	if apiProxy != "" {
		apiProxyURL, err := url.Parse(apiProxy)
		if err != nil {
			return nil, fmt.Errorf("unable to parse API proxy URL %q: %w", apiProxy, err)
		}
		pxDialer, err := xproxy.FromURL(apiProxyURL, seclientDialer)
		if err != nil {
			return nil, fmt.Errorf("unable to instantiate API proxy dialer %q: %w", apiProxy, err)
		}
		seclientDialer = pxDialer.(dialer.ContextDialer)
	}
	if args.apiAddress != "" {
		seclientDialer = dialer.NewFixedDialer(args.apiAddress, seclientDialer)
	} else if len(args.bootstrapDNS.values) > 0 {
		resolver, err := resolver.FastFromURLs(caPool, args.bootstrapDNS.values...)
		if err != nil {
			return nil, fmt.Errorf("unable to instantiate DNS resolver: %w", err)
		}
		seclientDialer = dialer.NewResolvingDialer(resolver, seclientDialer)
	}

	// TLS config for the API connection: SNI suppressed (or faked), cert
	// verification is skipped at the TLS layer because the API endpoint uses
	// a self-signed cert — actual peer verification happens in VerifyConnection
	// inside ProxyDialer for the proxy connections.
	tlsConfig := &tls.Config{
		ServerName:         args.fakeSNI,
		InsecureSkipVerify: true,
	}

	seclient, err := se.NewSEClient(args.apiLogin, args.apiPassword, buildAPITransport(
		seclientDialer.DialContext,
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := seclientDialer.DialContext(ctx, network, addr)
			if err != nil {
				return conn, err
			}
			return tls.Client(conn, tlsConfig), nil
		},
	))
	if err != nil {
		return nil, fmt.Errorf("unable to construct SEClient: %w", err)
	}
	seclient.Settings.ClientType = args.apiClientType
	seclient.Settings.ClientVersion = args.apiClientVersion
	seclient.Settings.UserAgent = args.apiUserAgent
	return seclient, nil
}

type apiProxyCandidateResult struct {
	candidate string
	client    *se.SEClient
	ips       []se.SEIPEntry
	countries []se.SEGeoEntry
	err       error
}

func callWithTimeout(parent context.Context, timeout time.Duration, f func(context.Context) error) error {
	ctx, cl := context.WithTimeout(parent, timeout)
	defer cl()
	return f(ctx)
}

func testAPIProxyCandidate(ctx context.Context, args *CLIArgs, baseDialer dialer.ContextDialer, caPool *x509.CertPool, candidate string, needDiscover bool, needCountries bool) apiProxyCandidateResult {
	result := apiProxyCandidateResult{candidate: candidate}

	client, err := newSEClient(args, baseDialer, caPool, candidate)
	if err != nil {
		result.err = err
		return result
	}

	if err := callWithTimeout(ctx, args.timeout, client.AnonRegister); err != nil {
		result.err = fmt.Errorf("anonymous registration failed: %w", err)
		return result
	}

	if err := callWithTimeout(ctx, args.timeout, client.RegisterDevice); err != nil {
		result.err = fmt.Errorf("device registration failed: %w", err)
		return result
	}

	if needCountries {
		var countries []se.SEGeoEntry
		if err := callWithTimeout(ctx, args.timeout, func(reqCtx context.Context) error {
			var geoErr error
			countries, geoErr = client.GeoList(reqCtx)
			return geoErr
		}); err != nil {
			result.err = fmt.Errorf("geo list request failed: %w", err)
			return result
		}
		result.countries = countries
	}

	if needDiscover {
		var ips []se.SEIPEntry
		if args.listProxiesAll {
			ips, err = discoverAllCountriesWithContext(ctx, args, client, nil, args.country)
		} else {
			ips, err = discoverCountryWithContext(ctx, args, client, nil, args.country)
		}
		if err != nil {
			result.err = fmt.Errorf("discover request failed: %w", err)
			return result
		}
		if len(ips) == 0 {
			result.err = errors.New("discover request returned an empty endpoints list")
			return result
		}
		result.ips = ips
	}

	result.client = client
	return result
}

func selectAPIProxyCandidate(args *CLIArgs, baseDialer dialer.ContextDialer, caPool *x509.CertPool, logger *clog.CondLogger, candidates []string, needDiscover bool, needCountries bool) (apiProxyCandidateResult, error) {
	if len(candidates) == 0 {
		return apiProxyCandidateResult{}, errors.New("no API proxy candidates provided")
	}

	parallelism := args.apiProxyParallel
	if parallelism > len(candidates) {
		parallelism = len(candidates)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type candidateJob struct {
		idx       int
		candidate string
	}

	jobs := make(chan candidateJob)
	results := make(chan apiProxyCandidateResult, len(candidates))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for job := range jobs {
			if ctx.Err() != nil {
				return
			}
			logger.Info("Trying API proxy candidate #%d/%d: %s", job.idx+1, len(candidates), job.candidate)
			result := testAPIProxyCandidate(ctx, args, baseDialer, caPool, job.candidate, needDiscover, needCountries)
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}
	}

	wg.Add(parallelism)
	for i := 0; i < parallelism; i++ {
		go worker()
	}

	go func() {
		defer close(jobs)
		for idx, candidate := range candidates {
			select {
			case jobs <- candidateJob{idx: idx, candidate: candidate}:
			case <-ctx.Done():
				return
			}
		}
	}()

	var lastErr error
	for i := 0; i < len(candidates); i++ {
		result := <-results
		if result.err == nil {
			logger.Info("Using API proxy candidate: %s", result.candidate)
			cancel()
			wg.Wait()
			return result, nil
		}
		lastErr = result.err
		logger.Warning("API proxy candidate %s failed: %v", result.candidate, result.err)
	}

	cancel()
	wg.Wait()
	if lastErr == nil {
		lastErr = errors.New("all API proxy candidates failed")
	}
	return apiProxyCandidateResult{}, lastErr
}

func run() int {
	args := parse_args()
	if args.showVersion {
		fmt.Println(version())
		return 0
	}
	if args.fetchFreeProxyOut != "" {
		count, err := fetchFreeProxyToFile(args.fetchFreeProxyURL, args.fetchFreeProxyOut, args.timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch free proxy list: %v\n", err)
			return 19
		}
		fmt.Printf("Saved %d proxies to %s\n", count, args.fetchFreeProxyOut)
		return 0
	}

	// When verbosity >= SILENT, pass io.Discard to NewLogWriter so it returns
	// a zero-cost nullLogWriter: no goroutine is started, nothing is written.
	logDst := io.Writer(os.Stderr)
	if args.verbosity >= clog.SILENT {
		logDst = io.Discard
	}
	logWriter := clog.NewLogWriter(logDst)
	defer logWriter.Close()

	mainLogger := clog.NewCondLogger(log.New(logWriter, "MAIN    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	proxyLogger := clog.NewCondLogger(log.New(logWriter, "PROXY   : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	// The go-socks5 library logs via a raw *log.Logger (bypasses CondLogger).
	// When verbosity >= SILENT, logWriter is already a nullLogWriter, so
	// this logger is also silenced automatically without extra branching.
	socksLogger := log.New(logWriter, "SOCKS   : ",
		log.LstdFlags|log.Lshortfile)

	mainLogger.Info("opera-proxy client version %s is starting...", version())

	proxyBlacklist, err := loadProxyBlacklist(args.proxyBlacklistFile)
	if err != nil {
		mainLogger.Error("Can't load proxy blacklist file %q: %v", args.proxyBlacklistFile, err)
		return 18
	}
	args.proxyBlacklist = proxyBlacklist
	if len(args.proxyBlacklist) > 0 {
		mainLogger.Info("Loaded %d blacklisted proxy endpoints from %s.", len(args.proxyBlacklist), args.proxyBlacklistFile)
	}

	var d dialer.ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	caPool, exitCode := buildCAPool(args.caFile, mainLogger)
	if exitCode != 0 {
		return exitCode
	}

	xproxy.RegisterDialerType("http", proxyFromURLWrapper)
	xproxy.RegisterDialerType("https", proxyFromURLWrapper)
	directDialer := d
	if args.proxy != "" {
		proxyURL, err := url.Parse(args.proxy)
		if err != nil {
			mainLogger.Critical("Unable to parse base proxy URL: %v", err)
			return 6
		}
		pxDialer, err := xproxy.FromURL(proxyURL, d)
		if err != nil {
			mainLogger.Critical("Unable to instantiate base proxy dialer: %v", err)
			return 7
		}
		d = pxDialer.(dialer.ContextDialer)
	}
	if len(args.proxyBypass.values) == 0 {
		fallbackPatterns, err := loadProxyBypassList(proxyBypassPathForFallback())
		if err == nil {
			args.proxyBypass.values = fallbackPatterns
		} else if !errors.Is(err, os.ErrNotExist) {
			mainLogger.Critical("Unable to load proxy bypass list: %v", err)
			return 7
		}
	}
	mainLogger.Info("Proxy bypass loaded: %d rule(s).", len(args.proxyBypass.values))

	// rootCtx is cancelled on SIGINT/SIGTERM so retry waits and background
	// tickers stop cleanly instead of blocking on time.Sleep or running forever.
	rootCtx, rootCancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer rootCancel()

	try := retryPolicy(rootCtx, args.initRetries, args.initRetryInterval, mainLogger)
	if args.apiAddress != "" {
		mainLogger.Info("Using fixed API host address = %s", args.apiAddress)
	}

	var (
		seclient           *se.SEClient
		ips                []se.SEIPEntry
		preloadedDiscovery bool
	)

	if args.apiProxyListURL != "" || args.apiProxyFile != "" {
		var (
			candidates []string
			err        error
		)
		if args.apiProxyListURL != "" {
			downloadTransport := buildSETransport(d.DialContext, nil)
			candidates, err = loadAPIProxyListFromURL(args.apiProxyListURL, downloadTransport, args.timeout)
			if err != nil {
				if args.apiProxyFile == "" {
					mainLogger.Critical("Unable to load API proxy list from URL: %v", err)
					return 8
				}
				mainLogger.Warning("Unable to load API proxy list from URL %q, falling back to file %q: %v", args.apiProxyListURL, args.apiProxyFile, err)
			}
		}
		if len(candidates) == 0 {
			candidates, err = loadAPIProxyList(args.apiProxyFile)
			if err != nil {
				mainLogger.Critical("Unable to load API proxy list: %v", err)
				return 8
			}
		}
		if args.apiProxy != "" {
			explicitProxy, err := normalizeAPIProxy(args.apiProxy)
			if err != nil {
				mainLogger.Critical("Unable to parse explicit API proxy: %v", err)
				return 6
			}
			filtered := make([]string, 0, len(candidates)+1)
			filtered = append(filtered, explicitProxy)
			for _, candidate := range candidates {
				if candidate == explicitProxy {
					continue
				}
				filtered = append(filtered, candidate)
			}
			candidates = filtered
		}
		parallelism := args.apiProxyParallel
		if parallelism > len(candidates) {
			parallelism = len(candidates)
		}
		mainLogger.Info("Loaded %d API proxy candidates. Testing up to %d in parallel.", len(candidates), parallelism)

		needDiscover := args.listProxies || args.listProxiesAll || args.dpExport || args.overrideProxyAddress == ""
		result, err := selectAPIProxyCandidate(args, d, caPool, mainLogger, candidates, needDiscover, args.listCountries)
		if err != nil {
			mainLogger.Critical("All API proxy candidates failed. Last error: %v", err)
			return 12
		}
		seclient = result.client
		ips = result.ips
		preloadedDiscovery = len(ips) > 0
		args.apiProxy = result.candidate
		if args.listCountries {
			return printCountryList(result.countries)
		}
	} else {
		seclientDialer := d
		if args.apiProxy != "" {
			apiProxyURL, err := url.Parse(args.apiProxy)
			if err != nil {
				mainLogger.Critical("Unable to parse api-proxy URL: %v", err)
				return 6
			}
			pxDialer, err := xproxy.FromURL(apiProxyURL, seclientDialer)
			if err != nil {
				mainLogger.Critical("Unable to instantiate api-proxy dialer: %v", err)
				return 7
			}
			seclientDialer = pxDialer.(dialer.ContextDialer)
		}
		if args.apiAddress != "" {
			seclientDialer = dialer.NewFixedDialer(args.apiAddress, seclientDialer)
		} else if len(args.bootstrapDNS.values) > 0 {
			res, err := resolver.FastFromURLs(caPool, args.bootstrapDNS.values...)
			if err != nil {
				mainLogger.Critical("Unable to instantiate DNS resolver: %v", err)
				return 4
			}
			seclientDialer = dialer.NewResolvingDialer(res, seclientDialer)
		}

		// Dialing w/o SNI, receiving self-signed certificate, so skip verification.
		// Either way we'll validate certificate of actual proxy server.
		tlsConfig := &tls.Config{
			ServerName:         args.fakeSNI,
			InsecureSkipVerify: true,
		}
		dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := seclientDialer.DialContext(ctx, network, addr)
			if err != nil {
				return conn, err
			}
			return tls.Client(conn, tlsConfig), nil
		}
		seclient, err = se.NewSEClient(args.apiLogin, args.apiPassword,
			buildSETransport(seclientDialer.DialContext, dialTLS))
		if err != nil {
			mainLogger.Critical("Unable to construct SEClient: %v", err)
			return 8
		}
		seclient.Settings.ClientType = args.apiClientType
		seclient.Settings.ClientVersion = args.apiClientVersion
		seclient.Settings.UserAgent = args.apiUserAgent

		err = try("anonymous registration", func() error {
			ctx, cl := context.WithTimeout(rootCtx, args.timeout)
			defer cl()
			return seclient.AnonRegister(ctx)
		})
		if err != nil {
			return 9
		}

		err = try("device registration", func() error {
			ctx, cl := context.WithTimeout(rootCtx, args.timeout)
			defer cl()
			return seclient.RegisterDevice(ctx)
		})
		if err != nil {
			return 10
		}

		if args.listCountries {
			return printCountries(try, mainLogger, args.timeout, seclient)
		}
	}

	proxyTLSServerName := func(entry se.SEIPEntry) string {
		if strings.TrimSpace(entry.Host) != "" {
			return entry.Host
		}
		return fmt.Sprintf("%s0.%s", strings.ToLower(entry.Geo.CountryCode), PROXY_SUFFIX)
	}

	handlerDialerFactory := func(entry se.SEIPEntry, endpointAddr string) dialer.ContextDialer {
		return dialer.NewProxyDialer(
			dialer.WrapStringToCb(endpointAddr),
			dialer.WrapStringToCb(proxyTLSServerName(entry)),
			dialer.WrapStringToCb(args.fakeSNI),
			func() (string, error) {
				return dialer.BasicAuthHeader(seclient.GetProxyCredentials()), nil
			},
			caPool,
			d)
	}

	if args.listProxies || args.listProxiesAll || args.dpExport {
		if !preloadedDiscovery {
			err = try("discover", func() error {
				var discoverErr error
				if args.listProxiesAll {
					ips, discoverErr = discoverAllCountries(args, seclient, mainLogger)
				} else {
					ips, discoverErr = discoverCountry(args, seclient, mainLogger, args.country)
				}
				if discoverErr != nil {
					return discoverErr
				}
				if len(ips) == 0 {
					return errors.New("empty endpoints list!")
				}
				return nil
			})
			if err != nil {
				return 12
			}
		}
		if args.listProxies || args.listProxiesAll {
			var speedResults map[proxyEndpointKey]proxySpeedResult
			if args.estimateProxySpeed {
				mainLogger.Info("Measuring proxy response time for %d endpoints using %q.", countProxyPorts(ips), args.proxySpeedTestURL)
				speedResults = benchmarkProxyEndpoints(rootCtx, args, ips, caPool, mainLogger, handlerDialerFactory)
			}
			if args.listProxiesAllOut != "" {
				if err := writeProxyCSV(args.listProxiesAllOut, ips, seclient, speedResults, args.sortProxiesBy); err != nil {
					mainLogger.Critical("Unable to write proxy CSV: %v", err)
					return 17
				}
				fmt.Printf("Proxy list saved to %s\n", args.listProxiesAllOut)
				return 0
			}
			return printProxies(ips, seclient, speedResults, args.sortProxiesBy)
		}
		if args.dpExport {
			return dpExport(ips, seclient, args.fakeSNI)
		}
	}

	var handlerDialer dialer.ContextDialer

	if args.overrideProxyAddress == "" {
		if !preloadedDiscovery {
			err = try("discover", func() error {
				res, err := discoverCountry(args, seclient, mainLogger, args.country)
				if err != nil {
					return err
				}
				if len(res) == 0 {
					return errors.New("empty endpoints list!")
				}
				ips = res
				return nil
			})
			if err != nil {
				return 12
			}
		}

		mainLogger.Info("Discovered endpoints: %v. Starting server selection routine %q.", ips, args.serverSelection.value)
		err = func() error {
			var ss dialer.SelectionFunc
			switch args.serverSelection.value {
			case dialer.ServerSelectionFirst:
				ss = dialer.SelectFirst
			case dialer.ServerSelectionRandom:
				ss = dialer.SelectRandom
			case dialer.ServerSelectionFastest:
				ss = dialer.NewFastestServerSelectionFunc(
					args.serverSelectionTestURL,
					args.serverSelectionDLLimit,
					&tls.Config{RootCAs: caPool},
				)
			default:
				panic("unhandled server selection value got past parsing")
			}
			dialers := make([]dialer.ContextDialer, len(ips))
			for i, ep := range ips {
				dialers[i] = handlerDialerFactory(ep, ep.NetAddr())
			}
			ctx, cl := context.WithTimeout(rootCtx, args.serverSelectionTimeout)
			defer cl()
			handlerDialer, err = ss(ctx, dialers)
			if err != nil {
				return err
			}
			if addresser, ok := handlerDialer.(interface{ Address() (string, error) }); ok {
				if epAddr, err := addresser.Address(); err == nil {
					mainLogger.Info("Selected endpoint address: %s", epAddr)
				}
			}
			return nil
		}()
		if err != nil {
			return 12
		}
	} else {
		sanitizedEndpoint := sanitizeFixedProxyAddress(args.overrideProxyAddress)
		if _, ok := args.proxyBlacklist[sanitizedEndpoint]; ok {
			mainLogger.Critical("Endpoint override %s is blacklisted.", sanitizedEndpoint)
			return 12
		}
		handlerDialer = handlerDialerFactory(se.SEIPEntry{
			Geo: se.SEGeoEntry{
				CountryCode: args.country,
			},
		}, sanitizedEndpoint)
		mainLogger.Info("Endpoint override: %s", sanitizedEndpoint)
	}
	if len(args.proxyBypass.values) > 0 {
		bypassDialer, err := dialer.NewBypassDialer(args.proxyBypass.values, directDialer, handlerDialer)
		if err != nil {
			mainLogger.Critical("Unable to configure proxy bypass rules: %v", err)
			return 7
		}
		handlerDialer = bypassDialer
	}

	clock.RunTicker(rootCtx, args.refresh, args.refreshRetry, func(ctx context.Context) error {
		mainLogger.Info("Refreshing login...")
		reqCtx, cl := context.WithTimeout(ctx, args.timeout)
		defer cl()
		if err := seclient.Login(reqCtx); err != nil {
			mainLogger.Error("Login refresh failed: %v", err)
			return err
		}
		mainLogger.Info("Login refreshed.")

		mainLogger.Info("Refreshing device password...")
		reqCtx, cl = context.WithTimeout(ctx, args.timeout)
		defer cl()
		if err := seclient.DeviceGeneratePassword(reqCtx); err != nil {
			mainLogger.Error("Device password refresh failed: %v", err)
			return err
		}
		mainLogger.Info("Device password refreshed.")
		return nil
	})

	mainLogger.Info("Starting proxy server...")
	if args.socksMode {
		socks, initError := handler.NewSocksServer(handlerDialer, socksLogger)
		if initError != nil {
			mainLogger.Critical("Failed to start: %v", initError)
			return 16
		}
		mainLogger.Info("Init complete.")
		err = socks.ListenAndServe("tcp", args.bindAddress)
	} else {
		h := handler.NewProxyHandler(handlerDialer, proxyLogger)
		mainLogger.Info("Init complete.")
		err = http.ListenAndServe(args.bindAddress, h)
	}
	mainLogger.Critical("Server terminated with a reason: %v", err)
	mainLogger.Info("Shutting down...")
	return 0
}

func printCountryList(list []se.SEGeoEntry) int {
	wr := csv.NewWriter(os.Stdout)
	defer wr.Flush()
	if err := wr.Write([]string{"country code", "country name"}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write country list: %v\n", err)
		return 1
	}
	for _, country := range list {
		if err := wr.Write([]string{country.CountryCode, country.Country}); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write country list: %v\n", err)
			return 1
		}
	}
	return 0
}

func printCountries(try func(string, func() error) error, logger *clog.CondLogger, timeout time.Duration, seclient *se.SEClient) int {
	var list []se.SEGeoEntry
	err := try("geolist", func() error {
		ctx, cl := context.WithTimeout(context.Background(), timeout)
		defer cl()
		l, err := seclient.GeoList(ctx)
		list = l
		return err
	})
	if err != nil {
		return 11
	}
	return printCountryList(list)
}

func printProxies(ips []se.SEIPEntry, seclient *se.SEClient, speedResults map[proxyEndpointKey]proxySpeedResult, sortBy string) int {
	login, password := seclient.GetProxyCredentials()
	fmt.Println("Proxy login:", login)
	fmt.Println("Proxy password:", password)
	fmt.Println("Proxy-Authorization:", dialer.BasicAuthHeader(login, password))
	fmt.Println("")
	if err := emitProxyCSV(os.Stdout, ips, speedResults, sortBy); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write proxy CSV: %v\n", err)
		return 1
	}
	return 0
}

func writeProxyCSV(filename string, ips []se.SEIPEntry, seclient *se.SEClient, speedResults map[proxyEndpointKey]proxySpeedResult, sortBy string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return emitProxyCSV(f, ips, speedResults, sortBy)
}

func emitProxyCSV(w io.Writer, ips []se.SEIPEntry, speedResults map[proxyEndpointKey]proxySpeedResult, sortBy string) error {
	wr := csv.NewWriter(w)
	defer wr.Flush()
	header := []string{"country_code", "country_name", "host", "ip_address", "port"}
	includeSpeed := speedResults != nil
	if includeSpeed {
		header = append(header, "speed_ms", "speed_status")
	}
	if err := wr.Write(header); err != nil {
		return err
	}
	rows := buildProxyRows(ips, speedResults, sortBy)
	for _, rowData := range rows {
		row := []string{
			rowData.CountryCode,
			rowData.CountryName,
			rowData.Host,
			rowData.IP,
			fmt.Sprintf("%d", rowData.Port),
		}
		if includeSpeed {
			speedMs := ""
			status := "not_tested"
			if rowData.HasSpeed {
				if rowData.Speed.Err == nil {
					speedMs = fmt.Sprintf("%d", rowData.Speed.Duration.Milliseconds())
				}
				status = rowData.Speed.Status()
			}
			row = append(row, speedMs, status)
		}
		if err := wr.Write(row); err != nil {
			return err
		}
	}
	wr.Flush()
	return wr.Error()
}

func dpExport(ips []se.SEIPEntry, seclient *se.SEClient, sni string) int {
	wr := csv.NewWriter(os.Stdout)
	wr.Comma = ' '
	defer wr.Flush()
	creds := url.UserPassword(seclient.GetProxyCredentials())
	var gotOne bool
	for i, ip := range ips {
		if len(ip.Ports) == 0 {
			continue
		}
		u := url.URL{
			Scheme: "https",
			User:   creds,
			Host:   net.JoinHostPort(ip.IP, strconv.Itoa(int(ip.Ports[0]))),
			RawQuery: url.Values{
				"sni":      []string{sni},
				"peername": []string{fmt.Sprintf("%s%d.%s", strings.ToLower(ip.Geo.CountryCode), i, PROXY_SUFFIX)},
			}.Encode(),
		}
		key := "proxy"
		if gotOne {
			key = "#proxy"
		}
		wr.Write([]string{key, u.String()})
		gotOne = true
	}
	return 0
}

func sanitizeFixedProxyAddress(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "443")
}

func loadProxyBlacklist(filename string) (map[string]struct{}, error) {
	if filename == "" {
		return nil, nil
	}

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	blacklist := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		if line == "" {
			continue
		}
		blacklist[sanitizeFixedProxyAddress(line)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return blacklist, nil
}

func filterBlacklistedProxyEntries(entries []se.SEIPEntry, blacklist map[string]struct{}) ([]se.SEIPEntry, []string) {
	if len(blacklist) == 0 {
		return entries, nil
	}

	filtered := make([]se.SEIPEntry, 0, len(entries))
	blocked := make([]string, 0)
	blockedSeen := make(map[string]struct{})
	appendBlocked := func(addr string) {
		if _, ok := blockedSeen[addr]; ok {
			return
		}
		blockedSeen[addr] = struct{}{}
		blocked = append(blocked, addr)
	}

	for _, entry := range entries {
		if len(entry.Ports) == 0 {
			addr := net.JoinHostPort(entry.IP, "443")
			if _, ok := blacklist[addr]; ok {
				appendBlocked(addr)
				continue
			}
			filtered = append(filtered, entry)
			continue
		}

		ports := make([]uint16, 0, len(entry.Ports))
		for _, port := range entry.Ports {
			addr := net.JoinHostPort(entry.IP, strconv.Itoa(int(port)))
			if _, ok := blacklist[addr]; ok {
				appendBlocked(addr)
				continue
			}
			ports = append(ports, port)
		}
		if len(ports) == 0 {
			continue
		}
		filtered = append(filtered, se.SEIPEntry{
			Geo:   entry.Geo,
			IP:    entry.IP,
			Ports: ports,
		})
	}

	return filtered, blocked
}

type proxyEndpointKey struct {
	countryCode string
	ip          string
	port        uint16
}

type proxySpeedResult struct {
	Duration time.Duration
	Err      error
}

type proxyListRow struct {
	CountryCode string
	CountryName string
	Host        string
	IP          string
	Port        uint16
	Speed       proxySpeedResult
	HasSpeed    bool
}

func (r proxySpeedResult) Status() string {
	if r.Err == nil {
		return "ok"
	}
	return r.Err.Error()
}

func parseCountryFilters(raw string) ([]string, bool) {
	parts := strings.Split(raw, ",")
	res := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, part := range parts {
		country := strings.ToUpper(strings.TrimSpace(part))
		if country == "" {
			continue
		}
		if country == "ALL" || country == "*" {
			return nil, true
		}
		if _, ok := seen[country]; ok {
			continue
		}
		seen[country] = struct{}{}
		res = append(res, country)
	}
	return res, false
}

func proxyEndpointAddrs(entries []se.SEIPEntry) []string {
	addrs := make([]string, 0, countProxyPorts(entries))
	for _, entry := range entries {
		if len(entry.Ports) == 0 {
			addrs = append(addrs, net.JoinHostPort(entry.IP, "443"))
			continue
		}
		for _, port := range entry.Ports {
			addrs = append(addrs, net.JoinHostPort(entry.IP, strconv.Itoa(int(port))))
		}
	}
	return addrs
}

func discoverCountryWithContext(parent context.Context, args *CLIArgs, seclient *se.SEClient, logger *clog.CondLogger, countryCode string) ([]se.SEIPEntry, error) {
	if args.discoverCSV != "" {
		return loadProxyEntriesFromCSV(args.discoverCSV, countryCode, false, args.countryExplicit, args.proxyBlacklist)
	}

	seen := make(map[proxyEndpointKey]struct{})
	aggregated := make([]se.SEIPEntry, 0)
	requestedGeo := fmt.Sprintf("\"%s\",,", countryCode)
	for attempt := 1; attempt <= args.discoverRepeat; attempt++ {
		ctx, cl := context.WithTimeout(parent, args.timeout)
		res, err := seclient.Discover(ctx, requestedGeo)
		cl()
		if err != nil {
			if isSurfEasyDiscover801(err) {
				fallbackCSV := discoverCSVPathForFallback(args)
				if logger != nil {
					logger.Warning("Discover API returned 801 for country %s, falling back to CSV %q.", countryCode, fallbackCSV)
				}
				res, csvErr := loadProxyEntriesFromCSV(fallbackCSV, countryCode, false, args.countryExplicit, args.proxyBlacklist)
				if csvErr != nil {
					return nil, fmt.Errorf("discover API returned 801 and CSV fallback %q failed: %w", fallbackCSV, csvErr)
				}
				return res, nil
			}
			return nil, err
		}
		if logger != nil {
			logger.Info("Discover for country %s returned %d endpoints on pass #%d: %v", countryCode, len(res), attempt, proxyEndpointAddrs(res))
		}
		res, blocked := filterBlacklistedProxyEntries(res, args.proxyBlacklist)
		if logger != nil && len(blocked) > 0 {
			logger.Info("Discover for country %s skipped %d blacklisted endpoints on pass #%d: %v", countryCode, len(blocked), attempt, blocked)
		}
		aggregated = appendUniqueProxies(aggregated, res, seen)
	}
	sortProxyEntries(aggregated)
	return aggregated, nil
}

func discoverCountry(args *CLIArgs, seclient *se.SEClient, logger *clog.CondLogger, countryCode string) ([]se.SEIPEntry, error) {
	return discoverCountryWithContext(context.Background(), args, seclient, logger, countryCode)
}

func discoverAllCountriesWithContext(parent context.Context, args *CLIArgs, seclient *se.SEClient, logger *clog.CondLogger, countryFilter string) ([]se.SEIPEntry, error) {
	if args.discoverCSV != "" {
		return loadProxyEntriesFromCSV(args.discoverCSV, countryFilter, true, args.countryExplicit, args.proxyBlacklist)
	}

	ctx, cl := context.WithTimeout(parent, args.timeout)
	countries, err := seclient.GeoList(ctx)
	cl()
	if err != nil {
		return nil, err
	}

	filters, allCountries := parseCountryFilters(countryFilter)
	if !args.countryExplicit {
		allCountries = true
		filters = nil
	}
	allowed := make(map[string]struct{}, len(filters))
	for _, country := range filters {
		allowed[country] = struct{}{}
	}

	all := make([]se.SEIPEntry, 0)
	seen := make(map[proxyEndpointKey]struct{})
	for _, country := range countries {
		if !allCountries {
			if _, ok := allowed[strings.ToUpper(country.CountryCode)]; !ok {
				continue
			}
		}
		res, err := discoverCountryWithContext(parent, args, seclient, logger, country.CountryCode)
		if err != nil {
			return nil, fmt.Errorf("discover failed for country %s: %w", country.CountryCode, err)
		}
		all = appendUniqueProxies(all, res, seen)
	}
	if len(all) == 0 && !allCountries {
		return nil, fmt.Errorf("no countries matched filter %q", args.country)
	}
	sortProxyEntries(all)
	return all, nil
}

func discoverAllCountries(args *CLIArgs, seclient *se.SEClient, logger *clog.CondLogger) ([]se.SEIPEntry, error) {
	return discoverAllCountriesWithContext(context.Background(), args, seclient, logger, args.country)
}

func appendUniqueProxies(dst, src []se.SEIPEntry, seen map[proxyEndpointKey]struct{}) []se.SEIPEntry {
	for _, entry := range src {
		if len(entry.Ports) == 0 {
			key := proxyEndpointKey{
				countryCode: entry.Geo.CountryCode,
				ip:          entry.IP,
				port:        443,
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			dst = append(dst, se.SEIPEntry{
				Geo:   entry.Geo,
				Host:  entry.Host,
				IP:    entry.IP,
				Ports: []uint16{443},
			})
			continue
		}

		ports := make([]uint16, 0, len(entry.Ports))
		for _, port := range entry.Ports {
			key := proxyEndpointKey{
				countryCode: entry.Geo.CountryCode,
				ip:          entry.IP,
				port:        port,
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			ports = append(ports, port)
		}
		if len(ports) == 0 {
			continue
		}
		dst = append(dst, se.SEIPEntry{
			Geo:   entry.Geo,
			Host:  entry.Host,
			IP:    entry.IP,
			Ports: ports,
		})
	}
	return dst
}

func isSurfEasyDiscover801(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "code=801")
}

func discoverCSVPathForFallback(args *CLIArgs) string {
	if args.discoverCSV != "" {
		return args.discoverCSV
	}
	return DefaultDiscoverCSVFallback
}

func proxyBypassPathForFallback() string {
	return DefaultProxyBypassFallback
}

func loadProxyEntriesFromCSV(filename string, countryFilter string, allowAll bool, countryExplicit bool, blacklist map[string]struct{}) ([]se.SEIPEntry, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	indexByName := make(map[string]int, len(header))
	for i, name := range header {
		indexByName[strings.ToLower(strings.TrimSpace(name))] = i
	}

	requiredColumns := []string{"country_code", "ip_address", "port"}
	for _, col := range requiredColumns {
		if _, ok := indexByName[col]; !ok {
			return nil, fmt.Errorf("proxy CSV %q is missing required column %q", filename, col)
		}
	}

	filters, allCountries := parseCountryFilters(countryFilter)
	if allowAll && !countryExplicit {
		allCountries = true
		filters = nil
	}
	allowedCountries := make(map[string]struct{}, len(filters))
	for _, country := range filters {
		allowedCountries[country] = struct{}{}
	}

	seen := make(map[proxyEndpointKey]struct{})
	entries := make([]se.SEIPEntry, 0)
	lineNo := 1
	fieldValue := func(record []string, column string) (string, error) {
		idx := indexByName[column]
		if idx >= len(record) {
			return "", fmt.Errorf("proxy CSV %q line %d is missing value for %s", filename, lineNo, column)
		}
		return strings.TrimSpace(record[idx]), nil
	}
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read proxy CSV %q at line %d: %w", filename, lineNo+1, err)
		}
		lineNo++

		countryCodeValue, err := fieldValue(record, "country_code")
		if err != nil {
			return nil, err
		}
		countryCode := strings.ToUpper(countryCodeValue)
		if countryCode == "" {
			return nil, fmt.Errorf("proxy CSV %q line %d has empty country_code", filename, lineNo)
		}
		if !allCountries {
			if _, ok := allowedCountries[countryCode]; !ok {
				continue
			}
		}

		ipAddr, err := fieldValue(record, "ip_address")
		if err != nil {
			return nil, err
		}
		if ipAddr == "" {
			return nil, fmt.Errorf("proxy CSV %q line %d has empty ip_address", filename, lineNo)
		}
		if _, err := netip.ParseAddr(ipAddr); err != nil {
			return nil, fmt.Errorf("proxy CSV %q line %d has invalid ip_address %q: %w", filename, lineNo, ipAddr, err)
		}

		portValue, err := fieldValue(record, "port")
		if err != nil {
			return nil, err
		}
		portNum, err := strconv.ParseUint(portValue, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("proxy CSV %q line %d has invalid port %q: %w", filename, lineNo, portValue, err)
		}

		countryName := ""
		if idx, ok := indexByName["country_name"]; ok && idx < len(record) {
			countryName = strings.TrimSpace(record[idx])
		}
		hostName := ""
		if idx, ok := indexByName["host"]; ok && idx < len(record) {
			hostName = strings.TrimSpace(record[idx])
		}

		entry := se.SEIPEntry{
			Geo: se.SEGeoEntry{
				CountryCode: countryCode,
				Country:     countryName,
			},
			Host:  hostName,
			IP:    ipAddr,
			Ports: []uint16{uint16(portNum)},
		}
		entries = appendUniqueProxies(entries, []se.SEIPEntry{entry}, seen)
	}

	entries, _ = filterBlacklistedProxyEntries(entries, blacklist)
	if len(entries) == 0 {
		if allowAll {
			if allCountries {
				return nil, fmt.Errorf("no proxy endpoints found in CSV %q", filename)
			}
			return nil, fmt.Errorf("no proxy endpoints from CSV %q matched country filter %q", filename, countryFilter)
		}
		return nil, fmt.Errorf("no proxy endpoints from CSV %q matched country %q", filename, countryFilter)
	}

	sortProxyEntries(entries)
	return entries, nil
}

func sortProxyEntries(entries []se.SEIPEntry) {
	for i := range entries {
		slices.Sort(entries[i].Ports)
	}
	slices.SortFunc(entries, func(a, b se.SEIPEntry) int {
		if c := cmp.Compare(a.Geo.CountryCode, b.Geo.CountryCode); c != 0 {
			return c
		}
		if c := cmp.Compare(a.IP, b.IP); c != 0 {
			return c
		}
		leftPort, rightPort := uint16(443), uint16(443)
		if len(a.Ports) > 0 {
			leftPort = a.Ports[0]
		}
		if len(b.Ports) > 0 {
			rightPort = b.Ports[0]
		}
		return cmp.Compare(leftPort, rightPort)
	})
}

func countProxyPorts(entries []se.SEIPEntry) int {
	total := 0
	for _, entry := range entries {
		if len(entry.Ports) == 0 {
			total++
			continue
		}
		total += len(entry.Ports)
	}
	return total
}

func buildProxyRows(ips []se.SEIPEntry, speedResults map[proxyEndpointKey]proxySpeedResult, sortBy string) []proxyListRow {
	rows := make([]proxyListRow, 0, countProxyPorts(ips))
	for i, ip := range ips {
		ports := ip.Ports
		if len(ports) == 0 {
			ports = []uint16{443}
		}
		for _, port := range ports {
			row := proxyListRow{
				CountryCode: ip.Geo.CountryCode,
				CountryName: ip.Geo.Country,
				Host:        ip.Host,
				IP:          ip.IP,
				Port:        port,
			}
			if row.Host == "" {
				row.Host = fmt.Sprintf("%s%d.%s", strings.ToLower(ip.Geo.CountryCode), i, PROXY_SUFFIX)
			}
			if speedResults != nil {
				result, ok := speedResults[proxyEndpointKey{
					countryCode: ip.Geo.CountryCode,
					ip:          ip.IP,
					port:        port,
				}]
				row.HasSpeed = ok
				if ok {
					row.Speed = result
				}
			}
			rows = append(rows, row)
		}
	}

	sortProxyRows(rows, sortBy)

	return rows
}

func sortProxyRows(rows []proxyListRow, sortBy string) {
	slices.SortStableFunc(rows, func(left, right proxyListRow) int {
		switch sortBy {
		case "country":
			if c := cmp.Compare(left.CountryCode, right.CountryCode); c != 0 {
				return c
			}
			if c := cmp.Compare(left.CountryName, right.CountryName); c != 0 {
				return c
			}
			if c := cmp.Compare(left.IP, right.IP); c != 0 {
				return c
			}
			return cmp.Compare(left.Port, right.Port)
		case "ip":
			if c := cmp.Compare(left.IP, right.IP); c != 0 {
				return c
			}
			if c := cmp.Compare(left.Port, right.Port); c != 0 {
				return c
			}
			return cmp.Compare(left.CountryCode, right.CountryCode)
		default:
			leftOK := left.HasSpeed && left.Speed.Err == nil
			rightOK := right.HasSpeed && right.Speed.Err == nil
			if leftOK != rightOK {
				// Successful probes sort before failed ones.
				if leftOK {
					return -1
				}
				return 1
			}
			if leftOK && rightOK {
				if c := cmp.Compare(left.Speed.Duration, right.Speed.Duration); c != 0 {
					return c
				}
			}
			if c := cmp.Compare(left.CountryCode, right.CountryCode); c != 0 {
				return c
			}
			if c := cmp.Compare(left.IP, right.IP); c != 0 {
				return c
			}
			return cmp.Compare(left.Port, right.Port)
		}
	})
}

func benchmarkProxyEndpoints(benchCtx context.Context, args *CLIArgs, ips []se.SEIPEntry, caPool *x509.CertPool, logger *clog.CondLogger, dialerFactory func(se.SEIPEntry, string) dialer.ContextDialer) map[proxyEndpointKey]proxySpeedResult {
	results := make(map[proxyEndpointKey]proxySpeedResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, BENCH_WORKERS)

	for _, entry := range ips {
		ports := entry.Ports
		if len(ports) == 0 {
			ports = []uint16{443}
		}
		for _, port := range ports {
			key := proxyEndpointKey{
				countryCode: entry.Geo.CountryCode,
				ip:          entry.IP,
				port:        port,
			}
			endpoint := net.JoinHostPort(entry.IP, strconv.Itoa(int(port)))
			wg.Add(1)
			go func(entry se.SEIPEntry, key proxyEndpointKey, countryCode, endpoint string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				start := time.Now()
				ctx, cl := context.WithTimeout(benchCtx, args.proxySpeedTimeout)
				err := probeProxyEndpoint(ctx, dialerFactory(entry, endpoint), args.proxySpeedTestURL, args.proxySpeedDLLimit, &tls.Config{
					RootCAs: caPool,
				})
				cl()

				result := proxySpeedResult{
					Duration: time.Since(start),
					Err:      err,
				}

				mu.Lock()
				results[key] = result
				mu.Unlock()

				if err == nil {
					logger.Info("Speed probe for %s via %s completed in %d ms.", countryCode, endpoint, result.Duration.Milliseconds())
				} else {
					logger.Warning("Speed probe for %s via %s failed: %v", countryCode, endpoint, err)
				}
			}(entry, key, entry.Geo.CountryCode, endpoint)
		}
	}

	wg.Wait()
	return results
}

// probeProxyEndpoint delegates to dialer.ProbeDialer, which is the single
// canonical HTTP-probe implementation shared with server selection.
func probeProxyEndpoint(ctx context.Context, upstream dialer.ContextDialer, targetURL string, dlLimit int64, tlsClientConfig *tls.Config) error {
	return dialer.ProbeDialer(ctx, upstream, targetURL, dlLimit, tlsClientConfig)
}

func main() {
	os.Exit(run())
}

// retryPolicy returns a helper that calls f up to retries times (0 = infinite).
// Between attempts it waits retryInterval, but wakes up immediately if ctx is
// cancelled -- previously time.Sleep blocked even after Ctrl+C.
func retryPolicy(ctx context.Context, retries int, retryInterval time.Duration, logger *clog.CondLogger) func(string, func() error) error {
	return func(name string, f func() error) error {
		var err error
		for i := 1; retries <= 0 || i <= retries; i++ {
			if i > 1 {
				logger.Warning("Retrying action %q in %v...", name, retryInterval)
				select {
				case <-ctx.Done():
					return fmt.Errorf("retry cancelled: %w", ctx.Err())
				case <-time.After(retryInterval):
				}
			}
			if ctx.Err() != nil {
				return fmt.Errorf("retry cancelled: %w", ctx.Err())
			}
			logger.Info("Attempting action %q, attempt #%d...", name, i)
			err = f()
			if err == nil {
				logger.Info("Action %q succeeded on attempt #%d", name, i)
				return nil
			}
			logger.Warning("Action %q failed: %v", name, err)
		}
		logger.Critical("All attempts for action %q have failed. Last error: %v", name, err)
		return err
	}
}

func readConfig(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("unable to open config file %q: %w", filename, err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.Comma = ' '
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.ReuseRecord = true
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("configuration file parsing failed: %w", err)
		}
		switch len(record) {
		case 0:
			continue
		case 1:
			if err := flag.Set(record[0], "true"); err != nil {
				line, _ := r.FieldPos(0)
				return fmt.Errorf("error parsing config file %q at line %d (%#v): %w", filename, line, record, err)
			}
		case 2:
			if err := flag.Set(record[0], record[1]); err != nil {
				line, _ := r.FieldPos(0)
				return fmt.Errorf("error parsing config file %q at line %d (%#v): %w", filename, line, record, err)
			}
		default:
			unified := strings.Join(record[1:], " ")
			if err := flag.Set(record[0], unified); err != nil {
				line, _ := r.FieldPos(0)
				return fmt.Errorf("error parsing config file %q at line %d (%#v): %w", filename, line, record, err)
			}
		}
	}
	return nil
}

func version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return bi.Main.Version
}
