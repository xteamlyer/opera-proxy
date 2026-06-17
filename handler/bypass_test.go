package handler

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/xteamlyer/opera-proxy/dialer"
	clog "github.com/xteamlyer/opera-proxy/log"
)

type recordingDialer struct {
	name      string
	addresses []string
}

func (d *recordingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *recordingDialer) DialContext(_ context.Context, _ string, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, address)
	return nil, errors.New(d.name)
}

func testProxyLogger() *clog.CondLogger {
	return clog.NewCondLogger(log.New(io.Discard, "", 0), clog.CRITICAL)
}

func TestProxyHandlerBypassesHTTPRequestsByTargetHost(t *testing.T) {
	direct := &recordingDialer{name: "direct"}
	proxied := &recordingDialer{name: "proxied"}
	bypassDialer, err := dialer.NewBypassDialer([]string{"*.example.com"}, direct, proxied)
	if err != nil {
		t.Fatalf("NewBypassDialer() error = %v", err)
	}

	h := NewProxyHandler(bypassDialer, testProxyLogger(), "")
	req := httptest.NewRequest(http.MethodGet, "http://check.example.com/path", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("ServeHTTP() status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if len(direct.addresses) != 1 || direct.addresses[0] != "check.example.com:80" {
		t.Fatalf("direct dialer addresses = %#v, want []string{\"check.example.com:80\"}", direct.addresses)
	}
	if len(proxied.addresses) != 0 {
		t.Fatalf("proxied dialer should not be used, got %#v", proxied.addresses)
	}
}

func TestProxyHandlerBypassesConnectRequestsByTargetHost(t *testing.T) {
	direct := &recordingDialer{name: "direct"}
	proxied := &recordingDialer{name: "proxied"}
	bypassDialer, err := dialer.NewBypassDialer([]string{"*.example.com"}, direct, proxied)
	if err != nil {
		t.Fatalf("NewBypassDialer() error = %v", err)
	}

	h := NewProxyHandler(bypassDialer, testProxyLogger(), "")
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: "secure.example.com:443"},
		Host:       "secure.example.com:443",
		RequestURI: "secure.example.com:443",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("ServeHTTP() status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	if len(direct.addresses) != 1 || direct.addresses[0] != "secure.example.com:443" {
		t.Fatalf("direct dialer addresses = %#v, want []string{\"secure.example.com:443\"}", direct.addresses)
	}
	if len(proxied.addresses) != 0 {
		t.Fatalf("proxied dialer should not be used, got %#v", proxied.addresses)
	}
}
