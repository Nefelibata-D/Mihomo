package weightedsticky

import (
	"context"
	"errors"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// resilientProxy is one live selection for the official retry loop. It does
// not dial a plan: each call selects exactly one node from the connection's
// session, dials it once and returns the result. The official tunnel loop owns
// counting, slowdown and the outer context budget.
type resilientProxy struct {
	C.Proxy
	strategy *Strategy

	key        string
	host       string
	candidates []C.Proxy
}

var _ C.Proxy = (*resilientProxy)(nil)

func (p *resilientProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	session, finish, err := p.strategy.sessionFor(ctx, p.key, p.host, p.candidates)
	if finish != nil {
		defer finish()
	}
	if err != nil {
		return nil, err
	}

	proxy, err := session.next(p.candidates)
	if err != nil {
		return nil, err
	}

	conn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, stopRetry(ctxErr)
		}
		// A dial failure is safe to retry by the official loop. It is also the
		// trigger for the rate-limited management status query.
		p.strategy.attemptFailed(proxy)
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("weighted-sticky: candidate returned a nil connection")
	}

	if original := session.originalNodeName(); proxy.Name() != original {
		log.Debugln("weighted-sticky [%s]: failover %q -> %q", p.strategy.name, original, proxy.Name())
	}
	if err := session.install(proxy); err != nil {
		_ = conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, stopRetry(ctxErr)
		}
		return nil, err
	}

	handle := session.connectionHandle()
	if handle == nil {
		_ = conn.Close()
		return nil, stopRetry(ErrNoAvailableCandidates)
	}
	if !N.NeedHandshake(conn) {
		handle.Commit()
	}
	return &wsConn{
		Conn:      conn,
		handle:    handle,
		onFailure: p.strategy.firstFailureHook(proxy),
	}, nil
}

func (p *resilientProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	session, finish, err := p.strategy.sessionFor(ctx, p.key, p.host, p.candidates)
	if finish != nil {
		defer finish()
	}
	if err != nil {
		return nil, err
	}

	proxy, err := session.next(p.candidates)
	if err != nil {
		return nil, err
	}

	conn, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, stopRetry(ctxErr)
		}
		p.strategy.attemptFailed(proxy)
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("weighted-sticky: candidate returned a nil packet connection")
	}

	if original := session.originalNodeName(); proxy.Name() != original {
		log.Debugln("weighted-sticky [%s]: failover %q -> %q", p.strategy.name, original, proxy.Name())
	}
	if err := session.install(proxy); err != nil {
		_ = conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, stopRetry(ctxErr)
		}
		return nil, err
	}

	handle := session.connectionHandle()
	if handle == nil {
		_ = conn.Close()
		return nil, stopRetry(ErrNoAvailableCandidates)
	}
	handle.Commit()
	return &wsPacketConn{PacketConn: conn, handle: handle}, nil
}
