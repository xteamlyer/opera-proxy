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

	// Maximum bytes we'll buffer while reading a CONNECT response header.
	// Real responses are ~50 bytes; 64 KiB is a generous ceiling that guards
	// against a misbehaving upstream sending an unbounded header stream.
	connectResponseMaxHeaderBytes = 64 * 1024
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
		// Custom cert verification logic:
		// DO NOT send SNI extension of TLS ClientHello
		// DO peer certificate verification against specified servername
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

// readResponse reads the HTTP/1.1 response to a CONNECT request from a raw
// net.Conn without consuming any bytes past the \r\n\r\n header terminator.
//
// Why not bufio.Reader directly on the conn?
// bufio.Reader reads ahead in chunks — it would silently consume bytes from
// the beginning of the tunneled TLS stream, corrupting the connection.
//
// Solution: wrap conn in a TeeReader that copies every byte into hdrBuf as it
// is read. We drive reads through bufio.ReadString('\n') which is efficient
// (no per-byte syscall), but the underlying io.Reader is a LimitedReader over
// the TeeReader — so the raw conn only advances exactly as far as we read.
// http.ReadResponse then parses from the in-memory hdrBuf.
func readResponse(conn io.Reader, req *http.Request) (*http.Response, error) {
	var hdrBuf bytes.Buffer
	limited := &io.LimitedReader{
		R: io.TeeReader(conn, &hdrBuf),
		N: connectResponseMaxHeaderBytes,
	}
	br := bufio.NewReader(limited)

	for {
		if limited.N <= 0 {
			return nil, errors.New("CONNECT response header exceeds size limit")
		}
		_, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("reading CONNECT response: %w", err)
		}
		sl := hdrBuf.Bytes()
		if len(sl) >= 4 && bytes.Equal(sl[len(sl)-4:], []byte("\r\n\r\n")) {
			break
		}
		if err == io.EOF {
			break
		}
	}

	return http.ReadResponse(bufio.NewReader(&hdrBuf), req)
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
