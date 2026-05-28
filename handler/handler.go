package handler

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xteamlyer/opera-proxy/dialer"
	clog "github.com/xteamlyer/opera-proxy/log"
)

const (
	COPY_BUF    = 128 * 1024
	BAD_REQ_MSG = "Bad Request\n"

	// Reduced idle pool: the proxy handler makes upstream connections per request,
	// not persistent keep-alive sessions. 10 total / 2 per host is plenty and
	// avoids leaking hundreds of idle goroutines/sockets under bursty traffic.
	TRANSPORT_MAX_IDLE_CONNS          = 10
	TRANSPORT_MAX_IDLE_CONNS_PER_HOST = 2
	TRANSPORT_IDLE_CONN_TIMEOUT       = 60 * time.Second
)

// copyBufPool reuses 128 KiB buffers for bidirectional data relay,
// avoiding per-connection heap allocations.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, COPY_BUF)
		return &b
	},
}

// copyWithPool copies from src to dst using a pooled buffer.
// It is the single canonical copy helper used by proxy, proxyh2, and
// copyBody. Previously the code had two patterns:
//   - proxy/proxyh2 used io.CopyBuffer with a pooled buffer
//   - copyBody used a manual Read/Write loop with a pooled buffer + http.Flusher
//
// Unified here: copyWithPool is the raw copy (used for net.Conn relay),
// and copyBody adds the Flusher call on top of it for HTTP response streaming.
func copyWithPool(dst io.Writer, src io.Reader) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	io.CopyBuffer(dst, src, *bufp)
}

type ProxyHandler struct {
	logger        *clog.CondLogger
	dialer        dialer.ContextDialer
	httptransport http.RoundTripper
}

func NewProxyHandler(dialer dialer.ContextDialer, logger *clog.CondLogger) *ProxyHandler {
	httptransport := &http.Transport{
		MaxIdleConns:          TRANSPORT_MAX_IDLE_CONNS,
		MaxIdleConnsPerHost:   TRANSPORT_MAX_IDLE_CONNS_PER_HOST,
		IdleConnTimeout:       TRANSPORT_IDLE_CONN_TIMEOUT,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           dialer.DialContext,
	}
	return &ProxyHandler{
		logger:        logger,
		dialer:        dialer,
		httptransport: httptransport,
	}
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	conn, err := s.dialer.DialContext(ctx, "tcp", req.RequestURI)
	if err != nil {
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}

	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		// Upgrade client connection
		localconn, _, err := hijack(wr)
		if err != nil {
			s.logger.Error("Can't hijack client connection: %v", err)
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		// Inform client connection is built
		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)

		proxy(req.Context(), localconn, conn)
	} else if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn)
	} else {
		s.logger.Error("Unsupported protocol version: %s", req.Proto)
		http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
		return
	}
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
	req.RequestURI = ""
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http" // We can't access :scheme pseudo-header, so assume http
		req.URL.Host = req.Host
	}
	resp, err := s.httptransport.RoundTrip(req)
	if err != nil {
		s.logger.Error("HTTP fetch error: %v", err)
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body)
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 ||
		req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}
	delHopHeaders(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req)
	} else {
		s.HandleRequest(wr, req)
	}
}

// proxy relays data bidirectionally between two net.Conn until either the
// context is cancelled or both sides close.
func proxy(ctx context.Context, left, right net.Conn) {
	wg := sync.WaitGroup{}
	cpy := func(dst, src net.Conn) {
		defer wg.Done()
		copyWithPool(dst, src)
		dst.Close()
	}
	wg.Add(2)
	go cpy(left, right)
	go cpy(right, left)
	groupdone := make(chan struct{})
	go func() {
		wg.Wait()
		groupdone <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		left.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
}

// proxyh2 relays an HTTP/2 tunnel: leftreader/leftwriter are the HTTP/2 body
// streams, right is the raw upstream TCP connection.
func proxyh2(ctx context.Context, leftreader io.ReadCloser, leftwriter io.Writer, right net.Conn) {
	wg := sync.WaitGroup{}
	ltr := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		copyWithPool(dst, src)
		dst.Close()
	}
	rtl := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		// HTTP/2 writer side: flush after each chunk so the client receives
		// data progressively. copyBody handles the Flusher call.
		copyBody(dst, src)
	}
	wg.Add(2)
	go ltr(right, leftreader)
	go rtl(leftwriter, right)
	groupdone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		groupdone <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		leftreader.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Connection",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func hijack(hijackable interface{}) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := hijackable.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("Connection doesn't support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	var emptytime time.Time
	err = conn.SetDeadline(emptytime)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

func flush(flusher interface{}) bool {
	f, ok := flusher.(http.Flusher)
	if !ok {
		return false
	}
	f.Flush()
	return true
}

// copyBody copies an HTTP response body to dst, calling Flush after each
// chunk so the client receives data progressively (important for streaming
// responses). Uses copyWithPool internally to share the same pooled buffer.
func copyBody(wr io.Writer, body io.Reader) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	for {
		n, readErr := body.Read(*bufp)
		if n > 0 {
			_, writeErr := wr.Write((*bufp)[:n])
			flush(wr)
			if writeErr != nil {
				break
			}
		}
		if readErr != nil {
			break
		}
	}
}
