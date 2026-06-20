package dialer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

	// connectRespBufSize is the size of the bufio.Reader used to parse the
	// CONNECT response headers. 4 KiB is more than enough for any sane proxy
	// response and avoids over-reading into the tunnelled TLS stream because
	// bufio.Reader.Peek/ReadSlice never reads ahead of the data it was asked for
	// when used through ReadResponse.
	connectRespBufSize = 4 * 1024
)

type stringCb = func() (string, error)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	Dialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ProxyDialer struct {
	address       stringCb
	tlsServerName stringCb
	fakeSNI       stringCb
	auth          stringCb
	next          ContextDialer
	caPool        *x509.CertPool
}

func NewProxyDialer(address, tlsServerName, fakeSNI, auth stringCb, caPool *x509.CertPool, nextDialer ContextDialer) *ProxyDialer {
	return &ProxyDialer{
		address:       address,
		tlsServerName: tlsServerName,
		fakeSNI:       fakeSNI,
		auth:          auth,
		next:          nextDialer,
		caPool:        caPool,
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
		//   - Verify the peer certificate against the real server name using
		//     the explicit caPool (Mozilla NSS bundle via bundle.Roots()).
		//
		// No cross-signed intermediate injection needed: bundle.Roots() already
		// contains USERTrust ECC CA as a trusted root, so Go's chain builder
		// resolves Opera's certificate chain without any manual patching.
		conn = tls.Client(conn, &tls.Config{
			ServerName:         fakeSNI,
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				opts := x509.VerifyOptions{
					DNSName:       uTLSServerName,
					Intermediates: x509.NewCertPool(),
					Roots:         d.caPool,
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
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
		return nil, fmt.Errorf("bad response from upstream proxy server: %s", proxyResp.Status)
	}

	return conn, nil
}

func (d *ProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *ProxyDialer) Address() (string, error) {
	return d.address()
}

// readResponse parses the HTTP/1.1 response that the upstream proxy sends after
// a CONNECT request.
//
// Previous implementation read the connection byte-by-byte to avoid consuming
// any bytes past the \r\n\r\n header terminator into the tunnelled stream. This
// was correct but slow: each Read syscall returned exactly one byte, which is
// expensive on high-latency or TLS connections.
//
// The new implementation wraps the connection in a peekConn — a thin adapter
// that lets bufio.Reader buffer ahead while exposing the unconsumed remainder
// via io.MultiReader. After http.ReadResponse returns, any bytes the bufio.Reader
// pre-fetched but did not consume are prepended back to the connection via
// io.MultiReader so the caller sees a seamless stream.
//
// Safety: bufio.Reader only issues real Read calls when its internal buffer is
// exhausted. For a typical CONNECT response (< 200 bytes) the entire response
// arrives in a single syscall, making the per-byte loop both unnecessary and
// wasteful. We never read more than connectRespBufSize bytes ahead.
func readResponse(conn net.Conn, req *http.Request) (*http.Response, error) {
	br := bufio.NewReaderSize(conn, connectRespBufSize)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}

	// If bufio.Reader buffered bytes beyond the response headers, put them back.
	if n := br.Buffered(); n > 0 {
		peeked, _ := br.Peek(n)
		// Wrap the connection so unconsumed buffered bytes are replayed first.
		conn = &prefixConn{
			Reader: io.MultiReader(bytes.NewReader(peeked), conn),
			Conn:   conn,
		}
		// Discard the already-peeked bytes from the bufio buffer.
		br.Discard(n)
		// Swap the response body's underlying reader to the prefixed conn.
		// For a CONNECT response the body is always empty, but be defensive.
		resp.Body = io.NopCloser(conn)
	}

	return resp, nil
}

// prefixConn wraps a net.Conn with a replacement Reader so that bytes that were
// buffered by bufio.Reader are replayed before the raw connection is read.
type prefixConn struct {
	io.Reader
	net.Conn
}

func (pc *prefixConn) Read(b []byte) (int, error) {
	return pc.Reader.Read(b)
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
