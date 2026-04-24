package dialer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	PROXY_CONNECT_METHOD       = "CONNECT"
	PROXY_HOST_HEADER          = "Host"
	PROXY_AUTHORIZATION_HEADER = "Proxy-Authorization"

	// MISSING_CHAIN_CERT is a cross-signed intermediate certificate that bridges
	// "USERTrust ECC Certification Authority" (The USERTRUST Network) to the legacy
	// "AAA Certificate Services" root (Comodo).
	//
	// Opera proxy servers present a certificate chain that terminates at
	// USERTrust ECC CA, but do NOT include USERTrust ECC CA itself in the TLS
	// handshake. On modern systems USERTrust ECC CA is trusted directly, so
	// verification succeeds without this cert. On older systems (old Android,
	// unpatched Linux, custom CA stores) USERTrust ECC CA is absent, and
	// verification fails.
	//
	// The cross-signed cert below carries the exact same public key as
	// USERTrust ECC CA but is signed by the ubiquitous "AAA Certificate Services"
	// Comodo root, which is present virtually everywhere. Injecting it into the
	// Intermediates pool provides an alternative valid path to a trusted root.
	//
	// Valid until: 2028-12-31. When this cert expires it must be replaced.
	MISSING_CHAIN_CERT = `-----BEGIN CERTIFICATE-----
MIID0zCCArugAwIBAgIQVmcdBOpPmUxvEIFHWdJ1lDANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGqxUWqn5aCPnetUkb1PGWthL
q8bVttHmc3Gu3ZzWDGH926CJA7gFFOxXzu5dP+Ihs8731Ip54KODfi2X0GHE8Znc
JZFjq38wo7Rw4sehM5zzvy5cU7Ffs30yf4o043l5o4HyMIHvMB8GA1UdIwQYMBaA
FKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1
xmNjmjAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAI
MAYGBFUdIAAwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5j
b20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEM
BQADggEBABns652JLCALBIAdGN5CmXKZFjK9Dpx1WywV4ilAbe7/ctvbq5AfjJXy
ij0IckKJUAfiORVsAYfZFhr1wHUrxeZWEQff2Ji8fJ8ZOd+LygBkc7xGEJuTI42+
FsMuCIKchjN0djsoTI0DQoWz4rIjQtUfenVqGtF8qmchxDM6OW1TyaLtYiKou+JV
bJlsQ2uRl9EMC5MCHdK8aXdJ5htN978UeAOwproLtOGFfy/cQjutdAFI3tZs4RmY
CV4Ks2dH/hzg1cEo70qLRDEmBDeNiXQ2Lu+lIg+DdEmSx/cQwgwp+7e9un/jX9Wf
8qn0dNW44bOwgeThpWOjzOoEeJBuv/c=
-----END CERTIFICATE-----
`
)

// missingLink is the cross-signed intermediate parsed once at init time.
// parseMissingLink panics early (at program start) if the bundled PEM is
// somehow corrupted — better than a silent nil-deref later during TLS.
var missingLink = parseMissingLink()

func parseMissingLink() *x509.Certificate {
	block, _ := pem.Decode([]byte(MISSING_CHAIN_CERT))
	if block == nil {
		panic("opera-proxy: failed to PEM-decode bundled MISSING_CHAIN_CERT")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("opera-proxy: failed to parse bundled MISSING_CHAIN_CERT: " + err.Error())
	}
	return cert
}

type stringCb = func() (string, error)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	Dialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ProxyDialer struct {
	address                stringCb
	tlsServerName          stringCb
	fakeSNI                stringCb
	auth                   stringCb
	next                   ContextDialer
	intermediateWorkaround bool
	caPool                 *x509.CertPool
}

func NewProxyDialer(address, tlsServerName, fakeSNI, auth stringCb, intermediateWorkaround bool, caPool *x509.CertPool, nextDialer ContextDialer) *ProxyDialer {
	return &ProxyDialer{
		address:                address,
		tlsServerName:          tlsServerName,
		fakeSNI:                fakeSNI,
		auth:                   auth,
		next:                   nextDialer,
		intermediateWorkaround: intermediateWorkaround,
		caPool:                 caPool,
	}
}

func ProxyDialerFromURL(u *url.URL, next ContextDialer) (*ProxyDialer, error) {
	host := u.Hostname()
	port := u.Port()
	tlsServerName := ""
	var auth stringCb = nil

	switch strings.ToLower(u.Scheme) {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
		tlsServerName = host
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)

	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		auth = WrapStringToCb(BasicAuthHeader(username, password))
	}
	return NewProxyDialer(
		WrapStringToCb(address),
		WrapStringToCb(tlsServerName),
		WrapStringToCb(tlsServerName),
		auth,
		false,
		nil,
		next), nil
}

func (d *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("bad network specified for DialContext: only tcp is supported")
	}

	uAddress, err := d.address()
	if err != nil {
		return nil, err
	}
	conn, err := d.next.DialContext(ctx, "tcp", uAddress)
	if err != nil {
		return nil, err
	}

	uTLSServerName, err := d.tlsServerName()
	if err != nil {
		return nil, err
	}
	fakeSNI, err := d.fakeSNI()
	if err != nil {
		return nil, err
	}
	if uTLSServerName != "" {
		// Custom TLS verification strategy:
		//   - Do NOT send SNI in ClientHello (use fakeSNI, may be empty string).
		//   - Verify the peer certificate against the real server name.
		//   - Optionally inject the cross-signed intermediate (certchain workaround).
		conn = tls.Client(conn, &tls.Config{
			ServerName:         fakeSNI,
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				opts := x509.VerifyOptions{
					DNSName:       uTLSServerName,
					Intermediates: x509.NewCertPool(),
					Roots:         d.caPool,
				}
				needWorkaround := false
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
					// Detect if any intermediate was signed by USERTrust ECC CA
					// (AuthorityKeyId matches missingLink.SubjectKeyId).
					// If so, we must also inject the cross-signed version of that CA
					// so that old trust stores can build a path to a known root.
					if d.intermediateWorkaround && !needWorkaround &&
						bytes.Equal(cert.AuthorityKeyId, missingLink.SubjectKeyId) {
						needWorkaround = true
					}
				}
				if needWorkaround {
					opts.Intermediates.AddCert(missingLink)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		})
	}

	req := &http.Request{
		Method:     PROXY_CONNECT_METHOD,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RequestURI: address,
		Host:       address,
		Header: http.Header{
			PROXY_HOST_HEADER: []string{address},
		},
	}

	if d.auth != nil {
		auth, err := d.auth()
		if err != nil {
			return nil, err
		}
		req.Header.Set(PROXY_AUTHORIZATION_HEADER, auth)
	}

	rawreq, err := httputil.DumpRequest(req, false)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(rawreq)
	if err != nil {
		return nil, err
	}

	proxyResp, err := readResponse(conn, req)
	if err != nil {
		return nil, err
	}

	if proxyResp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("bad response from upstream proxy server: %s", proxyResp.Status))
	}

	return conn, nil
}

func (d *ProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *ProxyDialer) Address() (string, error) {
	return d.address()
}

// readResponse reads an HTTP/1.1 response from the raw conn after a CONNECT
// request. It reads byte-by-byte until the \r\n\r\n header terminator is found,
// then hands the accumulated bytes to http.ReadResponse.
//
// Note: byte-by-byte reading is intentional here — we do NOT want to over-read
// past the end of headers into the tunneled TLS stream.
func readResponse(r io.Reader, req *http.Request) (*http.Response, error) {
	endOfResponse := []byte("\r\n\r\n")
	buf := &bytes.Buffer{}
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n < 1 && err == nil {
			continue
		}

		buf.Write(b)
		sl := buf.Bytes()
		if len(sl) < len(endOfResponse) {
			continue
		}

		if bytes.Equal(sl[len(sl)-4:], endOfResponse) {
			break
		}

		if err != nil {
			return nil, err
		}
	}
	return http.ReadResponse(bufio.NewReader(buf), req)
}

func BasicAuthHeader(login, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(login+":"+password))
}

func WrapStringToCb(s string) func() (string, error) {
	return func() (string, error) {
		return s, nil
	}
}
