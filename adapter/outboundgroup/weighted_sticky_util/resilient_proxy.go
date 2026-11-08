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
	if err := ctx.Err(); err != nil {
		return nil, stopRetry(err)
	}
	candidates := p.candidates
	if p.strategy.candidates != nil {
		candidates = p.strategy.candidates()
	}
	var err error
	candidates, err = p.strategy.validateCandidates(candidates)
	if err != nil {
		return nil, stopRetry(err)
	}
	session, finish, err := p.strategy.sessionFor(ctx, p.key, p.host, candidates, metadata)
	if finish != nil {
		defer finish()
	}
	if err != nil {
		return nil, err
	}

	proxy, err := session.next(candidates)
	if err != nil {
		return nil, err
	}
	attempt := session.attemptCount()
	p.strategy.diagAddCount(proxy.Name(), diagMetricAttempt, 1)

	conn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, stopRetry(ctxErr)
		}
		if p.strategy.diagEnabled() {
			p.strategy.diagEmit("dial.failure", session.flow, map[string]any{
				"node":        proxy.Name(),
				"stage":       "dial",
				"error_class": diagErrorClass(err),
				"attempt":     attempt,
			})
			p.strategy.diagAddCount(proxy.Name(), diagMetricFailure, 1)
		}
		session.noteFailure(proxy)
		// A dial failure is safe to retry by the official loop. It is also the
		// official health-check trigger at the group boundary.
		return nil, err
	}
	if conn == nil {
		if p.strategy.diagEnabled() {
			p.strategy.diagEmit("dial.failure", session.flow, map[string]any{
				"node":        proxy.Name(),
				"stage":       "dial",
				"error_class": "nil_connection",
				"attempt":     attempt,
			})
			p.strategy.diagAddCount(proxy.Name(), diagMetricFailure, 1)
		}
		session.noteFailure(proxy)
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
	if switched, from := session.noteSuccess(proxy); switched {
		if p.strategy.diagEnabled() {
			p.strategy.diagEmit("dial.switch_open", session.flow, map[string]any{
				"node":    proxy.Name(),
				"from":    from,
				"stage":   "dial",
				"attempt": attempt,
			})
			p.strategy.diagAddCount(proxy.Name(), diagMetricSwitchOpen, 1)
		}
	}
	if !N.NeedHandshake(conn) {
		handle.Commit()
	}
	return &wsConn{
		Conn:      conn,
		handle:    handle,
		onFailure: p.strategy.firstFailureHook(proxy, session, attempt),
	}, nil
}

func (p *resilientProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, stopRetry(err)
	}
	candidates := p.candidates
	if p.strategy.candidates != nil {
		candidates = p.strategy.candidates()
	}
	var err error
	candidates, err = p.strategy.validateCandidates(candidates)
	if err != nil {
		return nil, stopRetry(err)
	}
	session, finish, err := p.strategy.sessionFor(ctx, p.key, p.host, candidates, metadata)
	if finish != nil {
		defer finish()
	}
	if err != nil {
		return nil, err
	}

	proxy, err := session.next(candidates)
	if err != nil {
		return nil, err
	}
	attempt := session.attemptCount()
	p.strategy.diagAddCount(proxy.Name(), diagMetricAttempt, 1)

	conn, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, stopRetry(ctxErr)
		}
		if p.strategy.diagEnabled() {
			p.strategy.diagEmit("dial.failure", session.flow, map[string]any{
				"node":        proxy.Name(),
				"stage":       "packet",
				"error_class": diagErrorClass(err),
				"attempt":     attempt,
			})
			p.strategy.diagAddCount(proxy.Name(), diagMetricFailure, 1)
		}
		session.noteFailure(proxy)
		return nil, err
	}
	if conn == nil {
		if p.strategy.diagEnabled() {
			p.strategy.diagEmit("dial.failure", session.flow, map[string]any{
				"node":        proxy.Name(),
				"stage":       "packet",
				"error_class": "nil_packet_connection",
				"attempt":     attempt,
			})
			p.strategy.diagAddCount(proxy.Name(), diagMetricFailure, 1)
		}
		session.noteFailure(proxy)
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
	if switched, from := session.noteSuccess(proxy); switched {
		if p.strategy.diagEnabled() {
			p.strategy.diagEmit("dial.switch_open", session.flow, map[string]any{
				"node":    proxy.Name(),
				"from":    from,
				"stage":   "packet",
				"attempt": attempt,
			})
			p.strategy.diagAddCount(proxy.Name(), diagMetricSwitchOpen, 1)
		}
	}
	return &wsPacketConn{PacketConn: conn, handle: handle}, nil
}
