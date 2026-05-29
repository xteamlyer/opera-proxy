package dialer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/Alexey71/go-multierror"
)

type ServerSelection int

const (
	_ = iota
	ServerSelectionFirst
	ServerSelectionRandom
	ServerSelectionFastest
)

func (ss ServerSelection) String() string {
	switch ss {
	case ServerSelectionFirst:
		return "first"
	case ServerSelectionRandom:
		return "random"
	case ServerSelectionFastest:
		return "fastest"
	default:
		return fmt.Sprintf("ServerSelection(%d)", int(ss))
	}
}

func ParseServerSelection(s string) (ServerSelection, error) {
	switch strings.ToLower(s) {
	case "first":
		return ServerSelectionFirst, nil
	case "random":
		return ServerSelectionRandom, nil
	case "fastest":
		return ServerSelectionFastest, nil
	}
	return 0, errors.New("unknown server selection strategy")
}

type SelectionFunc = func(ctx context.Context, dialers []ContextDialer) (ContextDialer, error)

func SelectFirst(_ context.Context, dialers []ContextDialer) (ContextDialer, error) {
	if len(dialers) == 0 {
		return nil, errors.New("empty dialers list")
	}
	return dialers[0], nil
}

func SelectRandom(_ context.Context, dialers []ContextDialer) (ContextDialer, error) {
	if len(dialers) == 0 {
		return nil, errors.New("empty dialers list")
	}
	return dialers[rand.IntN(len(dialers))], nil
}

// probeDialer delegates to ProbeDialer (dialer/probe.go) so the selection
// logic does not duplicate the HTTP probe implementation.
func probeDialer(ctx context.Context, d ContextDialer, url string, dlLimit int64, tlsClientConfig *tls.Config) error {
	return ProbeDialer(ctx, d, url, dlLimit, tlsClientConfig)
}

func NewFastestServerSelectionFunc(url string, dlLimit int64, tlsClientConfig *tls.Config) SelectionFunc {
	return func(ctx context.Context, dialers []ContextDialer) (ContextDialer, error) {
		var resErr error
		ctx, cl := context.WithCancel(ctx)
		defer cl()
		errors := make(chan error)
		success := make(chan ContextDialer)
		for _, dialer := range dialers {
			go func(dialer ContextDialer) {
				err := probeDialer(ctx, dialer, url, dlLimit, tlsClientConfig)
				if err == nil {
					select {
					case success <- dialer:
					case <-ctx.Done():
					}
				} else {
					select {
					case errors <- err:
					case <-ctx.Done():
					}
				}
			}(dialer)
		}
		for _ = range dialers {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case d := <-success:
				return d, nil
			case err := <-errors:
				resErr = multierror.Append(resErr, err)
			}
		}
		return nil, resErr
	}
}
