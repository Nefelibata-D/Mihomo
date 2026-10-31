package weightedsticky

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sing/common/network"
)

// unsafeReplayError reports that a first write accepted business bytes and
// then failed. Re-sending the same payload could duplicate a POST or another
// non-idempotent request, so this error deliberately stops the official retry
// loop instead of letting the upstream loop replay it.
type unsafeReplayError struct {
	err error
}

func (e *unsafeReplayError) Error() string {
	return "weighted-sticky: partial first write cannot be retried safely: " + e.err.Error()
}

func (e *unsafeReplayError) Unwrap() error { return e.err }

func (e *unsafeReplayError) StopRetry() bool { return true }

// wsConn counts only positive-byte reads and writes. The UnwrapReader and
// UnwrapWriter counters keep renewal working on sing's zero-copy/splice and
// buffer paths, which bypass Read/Write after unwrapping.
type wsConn struct {
	C.Conn
	handle *Handle

	// onFailure reports a failed first write or first read before any response
	// byte arrived, with the actual phase and error. A VLESS rejection is only
	// visible at the first read, after the request was written, so this hook
	// also runs when a write succeeded.
	onFailure   func(failurePhase, error)
	failureOnce sync.Once
	closed      atomic.Bool

	stateMu     sync.Mutex
	readFailed  bool
	writeFailed bool
	wrote       bool
	gotData     bool
}

// localCancel reports a failure that the local side caused. Closing the
// connection or cancelling its context says nothing about the node: a blocked
// read often returns such an error after the application has gone away.
func (c *wsConn) localCancel(err error) bool {
	return c.closed.Load() || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

func (c *wsConn) noteReadFailure(err error) {
	c.stateMu.Lock()
	if c.readFailed {
		c.stateMu.Unlock()
		return
	}
	c.readFailed = true
	trigger := !c.gotData && c.onFailure != nil && !c.localCancel(err)
	c.stateMu.Unlock()
	if trigger {
		c.failureOnce.Do(func() { c.onFailure(failureFirstRead, err) })
	}
}

func (c *wsConn) noteWriteFailure(err error) {
	c.stateMu.Lock()
	if c.writeFailed {
		c.stateMu.Unlock()
		return
	}
	c.writeFailed = true
	trigger := !c.wrote && c.onFailure != nil && !c.localCancel(err)
	c.stateMu.Unlock()
	if trigger {
		c.failureOnce.Do(func() { c.onFailure(failureFirstWrite, err) })
	}
}

func (c *wsConn) markGotData() {
	c.stateMu.Lock()
	c.gotData = true
	c.stateMu.Unlock()
}

func (c *wsConn) markWrote() {
	c.stateMu.Lock()
	c.wrote = true
	c.stateMu.Unlock()
}

func (c *wsConn) isFirstWrite() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return !c.wrote
}

var _ C.Conn = (*wsConn)(nil)

func (c *wsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.markGotData()
		c.handle.Renew()
	} else if err != nil {
		c.noteReadFailure(err)
	}
	return n, err
}

func (c *wsConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.Conn.ReadBuffer(buffer)
	if buffer.Len() > 0 {
		c.markGotData()
		c.handle.Renew()
	} else if err != nil {
		c.noteReadFailure(err)
	}
	return err
}

func (c *wsConn) Write(p []byte) (int, error) {
	first := c.isFirstWrite()
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.markWrote()
		c.handle.Renew()
		if first && err != nil {
			// Business bytes were accepted by the wrapper before the failure.
			// The request is not replayable; report the site failure for the
			// next connection but stop this official loop.
			if c.onFailure != nil && !c.localCancel(err) {
				c.failureOnce.Do(func() { c.onFailure(failureFirstWrite, err) })
			}
			return n, &unsafeReplayError{err: err}
		}
	} else if err != nil {
		c.noteWriteFailure(err)
		if first && c.localCancel(err) {
			// The local side is gone. The official loop has nothing useful to
			// retry, and the failure must not be attributed to the node.
			return n, stopRetry(err)
		}
	}
	return n, err
}

func (c *wsConn) WriteBuffer(buffer *buf.Buffer) error {
	first := c.isFirstWrite()
	size := buffer.Len()
	err := c.Conn.WriteBuffer(buffer)
	if err == nil && size > 0 {
		c.markWrote()
		c.handle.Renew()
		return nil
	}
	if err == nil {
		return nil
	}
	if size > 0 {
		c.noteWriteFailure(err)
		if first {
			// WriteBuffer exposes no accepted-byte count; the only safe
			// assumption is that some payload may have been sent.
			if c.onFailure != nil && !c.localCancel(err) {
				c.failureOnce.Do(func() { c.onFailure(failureFirstWrite, err) })
			}
			return &unsafeReplayError{err: err}
		}
	}
	return err
}

func (c *wsConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.onFailure == nil {
		return c.Conn, []N.CountFunc{func(n int64) {
			if n > 0 {
				c.handle.Renew()
			}
		}}
	}
	// The resilience path must observe the first read error even when sing's
	// copy uses the unwrapped reader or the splice path. A plain wrapper keeps
	// that error visible; the count callback keeps activity renewal working.
	return &hookedReader{reader: c.Conn, conn: c}, []N.CountFunc{func(n int64) {
		if n > 0 {
			c.markGotData()
			c.handle.Renew()
		}
	}}
}

func (c *wsConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.onFailure == nil {
		return c.Conn, []N.CountFunc{func(n int64) {
			if n > 0 {
				c.handle.Renew()
			}
		}}
	}
	return &hookedWriter{writer: c.Conn, conn: c}, []N.CountFunc{func(n int64) {
		if n > 0 {
			c.markWrote()
			c.handle.Renew()
		}
	}}
}

type hookedReader struct {
	reader io.Reader
	conn   *wsConn
}

func (r *hookedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.conn.markGotData()
		r.conn.handle.Renew()
	} else if err != nil {
		r.conn.noteReadFailure(err)
	}
	return n, err
}

type hookedWriter struct {
	writer io.Writer
	conn   *wsConn
}

func (w *hookedWriter) Write(p []byte) (int, error) {
	first := w.conn.isFirstWrite()
	n, err := w.writer.Write(p)
	if n > 0 {
		w.conn.markWrote()
		w.conn.handle.Renew()
		if first && err != nil {
			if w.conn.onFailure != nil && !w.conn.localCancel(err) {
				w.conn.failureOnce.Do(func() { w.conn.onFailure(failureFirstWrite, err) })
			}
			return n, &unsafeReplayError{err: err}
		}
	} else if err != nil {
		w.conn.noteWriteFailure(err)
	}
	return n, err
}

// NeedHandshake preserves the early-connection contract of the wrapped conn.
func (c *wsConn) NeedHandshake() bool {
	if early, ok := c.Conn.(network.EarlyConn); ok {
		return early.NeedHandshake()
	}
	return false
}

// CloseWrite preserves half-close; without it Relay would fall back to closing
// the whole connection.
func (c *wsConn) CloseWrite() error {
	if closer, ok := c.Conn.(network.WriteCloser); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *wsConn) Close() error {
	c.closed.Store(true)
	err := c.Conn.Close()
	c.handle.Release()
	return err
}

// wsPacketConn renews on positive-byte datagrams in either direction.
type wsPacketConn struct {
	C.PacketConn
	handle *Handle
}

var _ C.PacketConn = (*wsPacketConn)(nil)

func (c *wsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.handle.Renew()
	}
	return n, addr, err
}

func (c *wsPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.handle.Renew()
	}
	return n, err
}

func (c *wsPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, addr, err = c.PacketConn.WaitReadFrom()
	if len(data) > 0 {
		c.handle.Renew()
	}
	return data, put, addr, err
}

func (c *wsPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.handle.Release()
	return err
}
