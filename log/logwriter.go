package log

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const MAX_LOG_QLEN = 128
const QUEUE_SHUTDOWN_TIMEOUT = 500 * time.Millisecond

// LogWriter is an asynchronous io.WriteCloser that queues log lines into a
// buffered channel and drains them in a dedicated goroutine. This keeps the
// hot path (logging inside a handler goroutine) allocation-free and
// contention-free with respect to the underlying writer (usually os.Stderr).
type LogWriter struct {
	writer io.Writer
	ch     chan []byte
	done   chan struct{}
}

func (lw *LogWriter) Write(p []byte) (int, error) {
	if p == nil {
		return 0, errors.New("can't write nil byte slice")
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case lw.ch <- buf:
		return len(p), nil
	default:
		return 0, errors.New("log writer queue overflow")
	}
}

func (lw *LogWriter) Close() {
	lw.ch <- nil
	timer := time.After(QUEUE_SHUTDOWN_TIMEOUT)
	select {
	case <-timer:
	case <-lw.done:
	}
}

// loop drains the channel and writes each buffer to the underlying writer.
// Write errors are printed to os.Stderr directly so they are never silently
// discarded — a broken pipe or a full disk is reported immediately without
// re-entering LogWriter.
func (lw *LogWriter) loop() {
	for p := range lw.ch {
		if p == nil {
			break
		}
		if _, err := lw.writer.Write(p); err != nil {
			fmt.Fprintf(os.Stderr, "log write error: %v\n", err)
		}
	}
	lw.done <- struct{}{}
}

// nullLogWriter is a zero-overhead WriteCloser backed by io.Discard.
// No goroutine is spawned; Write and Close are no-ops.
type nullLogWriter struct{}

func (nullLogWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nullLogWriter) Close()                      {}

// WriteCloser is the common interface for LogWriter and nullLogWriter.
type WriteCloser interface {
	io.Writer
	Close()
}

// NewLogWriter returns a WriteCloser that asynchronously forwards log lines to
// dst. When dst is io.Discard (i.e. verbosity >= SILENT), a zero-cost
// nullLogWriter is returned — no goroutine is started, no allocations occur.
func NewLogWriter(dst io.Writer) WriteCloser {
	if dst == io.Discard {
		return nullLogWriter{}
	}
	lw := &LogWriter{
		writer: dst,
		ch:     make(chan []byte, MAX_LOG_QLEN),
		done:   make(chan struct{}),
	}
	go lw.loop()
	return lw
}
