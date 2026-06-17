package handler

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/xteamlyer/opera-proxy/dialer"
)

// NewSocksServer creates a SOCKS5 server using the provided dialer.
// logger controls SOCKS-level diagnostic output; pass a logger backed by
// io.Discard to suppress all messages (e.g. when verbosity >= SILENT).
func NewSocksServer(dialer dialer.ContextDialer, logger *log.Logger) (*socks5.Server, error) {
	opts := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithRule(
			&socks5.PermitCommand{
				EnableConnect: true,
			},
		),
		socks5.WithResolver(DummySocksResolver{}),
		socks5.WithConnectHandle(func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
			return handleSocksConnect(ctx, writer, request, dialer)
		}),
	}
	return socks5.NewServer(opts...), nil
}

func handleSocksConnect(ctx context.Context, writer io.Writer, request *socks5.Request, upstream dialer.ContextDialer) error {
	target, err := upstream.DialContext(ctx, "tcp", request.DestAddr.String())
	if err != nil {
		reply := statute.RepHostUnreachable
		msg := err.Error()
		if strings.Contains(msg, "refused") {
			reply = statute.RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			reply = statute.RepNetworkUnreachable
		}
		if sendErr := socks5.SendReply(writer, reply, nil); sendErr != nil {
			return fmt.Errorf("failed to send reply, %v", sendErr)
		}
		return fmt.Errorf("connect to %v failed, %v", request.RawDestAddr, err)
	}

	if err := socks5.SendReply(writer, statute.RepSuccess, target.LocalAddr()); err != nil {
		target.Close()
		return fmt.Errorf("failed to send reply, %v", err)
	}

	clientConn, ok := writer.(net.Conn)
	if !ok {
		target.Close()
		return fmt.Errorf("writer is %T, expected net.Conn", writer)
	}

	proxy(ctx, clientConn, target)
	return nil
}

type DummySocksResolver struct{}

func (_ DummySocksResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
