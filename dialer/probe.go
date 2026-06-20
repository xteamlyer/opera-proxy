package dialer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	probeMaxIdleConns        = 100
	probeIdleConnTimeout     = 90 * time.Second
	probeTLSHandshakeTimeout = 10 * time.Second
	probeExpectContTimeout   = 1 * time.Second
)

// ProbeDialer checks whether dialer can reach targetURL by issuing a GET
// request and discarding up to dlLimit bytes of the response body (0 = no
// limit). It is used by both the server-selection benchmark
// (NewFastestServerSelectionFunc) and the stand-alone speed test
// (benchmarkProxyEndpoints in main.go).
//
// The http.Transport is explicitly closed via CloseIdleConnections after the
// probe completes. Without this, each call would leave an idle-connection
// goroutine and its associated socket running until the IdleConnTimeout
// expired — with hundreds of concurrent speed probes this caused significant
// goroutine and fd leakage.
func ProbeDialer(ctx context.Context, d ContextDialer, targetURL string, dlLimit int64, tlsClientConfig *tls.Config) error {
	t := &http.Transport{
		MaxIdleConns:          probeMaxIdleConns,
		IdleConnTimeout:       probeIdleConnTimeout,
		TLSHandshakeTimeout:   probeTLSHandshakeTimeout,
		ExpectContinueTimeout: probeExpectContTimeout,
		DialContext:           d.DialContext,
		TLSClientConfig:       tlsClientConfig,
		ForceAttemptHTTP2:     true,
	}
	// Always release idle connections when we are done with this one-shot
	// transport, regardless of whether the probe succeeds or fails.
	defer t.CloseIdleConnections()

	httpClient := http.Client{Transport: t}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code %d for URL %q", resp.StatusCode, targetURL)
	}

	rd := io.Reader(resp.Body)
	if dlLimit > 0 {
		rd = io.LimitReader(rd, dlLimit)
	}
	_, err = io.Copy(io.Discard, rd)
	return err
}
