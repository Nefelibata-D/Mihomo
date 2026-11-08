package weightedsticky

import (
	"errors"
	"sync"
	"time"
)

// ErrBindingCapacity reports that the cache is full of live bindings. A valid
// binding is never evicted to make room; the caller must surface this error.
var ErrBindingCapacity = errors.New("weighted-sticky: binding cache capacity exceeded")

// Binding is one website binding. The generation makes an old connection
// unable to renew or delete a binding created after it expired.
type Binding struct {
	key          string
	proxyName    string
	generation   uint64
	lastActivity time.Time
	refs         int
	committed    bool
}

// Handle owns one reference to a binding. release is idempotent, so a
// connection that is closed twice cannot decrement the count twice.
type Handle struct {
	cache   *Cache
	binding *Binding
	fresh   bool
	once    sync.Once
}

func (h *Handle) ProxyName() string {
	return h.binding.proxyName
}

func (h *Handle) Generation() uint64 {
	return h.binding.generation
}

// Fresh reports whether Acquire created this binding rather than reusing one.
// A fresh binding gets one attempt before alternatives, because its node was
// just chosen by weight and is not yet a bound hit.
func (h *Handle) Fresh() bool {
	return h.fresh
}

func (h *Handle) Commit() {
	h.cache.Commit(h.binding)
}

func (h *Handle) Renew() {
	h.cache.Renew(h.binding)
}

func (h *Handle) Release() {
	h.once.Do(func() {
		h.cache.Release(h.binding)
	})
}

// Cache is a small, purpose-built map: sliding expiry, generation
// isolation and a hard capacity limit. It deliberately does not use
// common/lru, whose size limit silently evicts entries and whose clock and
// renewal semantics cannot express the contract.
type Cache struct {
	mu             sync.Mutex
	entries        map[string]*Binding
	maxBindings    int
	idleTimeout    time.Duration
	now            func() time.Time
	nextGeneration uint64
}

func NewCache(maxBindings int, idleTimeout time.Duration, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{
		entries:     map[string]*Binding{},
		maxBindings: maxBindings,
		idleTimeout: idleTimeout,
		now:         now,
	}
}

func (c *Cache) expired(b *Binding, now time.Time) bool {
	return now.Sub(b.lastActivity) >= c.idleTimeout
}

// keepLocked reports whether a record with no active reference must stay in the
// cache. Only a committed binding stays for its idle window; an uncommitted
// reservation is dead as soon as its dial that has not carried traffic ends.
func (c *Cache) keepLocked(b *Binding, now time.Time) bool {
	return b.committed && !c.expired(b, now)
}

// Acquire returns a referenced handle for key. A live binding is reused; an
// expired or unusable one is replaced. Concurrent first use of the same key
// shares exactly one reservation. choose runs under the cache lock and must
// not perform I/O; it selects a candidate name for a new binding.
func (c *Cache) Acquire(key string, choose func() (string, error), usable func(string) bool) (*Handle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if b, ok := c.entries[key]; ok {
		live := !c.expired(b, now)
		stillUsable := usable == nil || usable(b.proxyName)
		if live && stillUsable {
			b.refs++
			// Concurrent first uses may share a reservation, but it is not a
			// cache hit until one connection actually commits it.
			return &Handle{cache: c, binding: b, fresh: !b.committed}, nil
		}
		// The record is no longer valid for new connections. Old handles keep
		// their pointer, but renewal and release check map identity and
		// generation before touching the replacement.
		delete(c.entries, key)
	}

	if len(c.entries) >= c.maxBindings {
		c.purgeExpiredLocked(now)
	}
	if len(c.entries) >= c.maxBindings {
		return nil, ErrBindingCapacity
	}

	name, err := choose()
	if err != nil {
		return nil, err
	}

	c.nextGeneration++
	b := &Binding{
		key:          key,
		proxyName:    name,
		generation:   c.nextGeneration,
		lastActivity: now,
		refs:         1,
	}
	c.entries[key] = b
	return &Handle{cache: c, binding: b, fresh: true}, nil
}

// purgeExpiredLocked removes records with no active reference that no longer
// carry a committed idle window.
func (c *Cache) purgeExpiredLocked(now time.Time) {
	for key, b := range c.entries {
		if b.refs == 0 && !c.keepLocked(b, now) {
			delete(c.entries, key)
		}
	}
}

// Rebind installs only over the expected generation; a late success cannot overwrite a newer binding.
func (c *Cache) Rebind(key string, expectedGeneration uint64, proxyName string) (*Handle, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	current, ok := c.entries[key]
	if !ok || current.generation != expectedGeneration {
		return nil, false
	}

	now := c.now()
	c.nextGeneration++
	b := &Binding{
		key:          key,
		proxyName:    proxyName,
		generation:   c.nextGeneration,
		lastActivity: now,
		refs:         1,
	}
	c.entries[key] = b
	return &Handle{cache: c, binding: b, fresh: false}, true
}

// PruneProxies removes bindings outside the configured names of all currently present servers.
// The list is bounded by the observed candidate names, so a deleted provider
// entry cannot leave a growing name history in the cache. An active
// connection keeps its own handle; renewal is ignored once the binding is no
// longer current, and the connection itself keeps working.
func (c *Cache) PruneProxies(keep map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, binding := range c.entries {
		if _, ok := keep[binding.proxyName]; !ok {
			delete(c.entries, key)
		}
	}
}

// Ref adds one reference to an existing binding for the established
// connection. Unlike Acquire it does not make the binding current again: a
// connection may finish on a binding that was already replaced.
func (c *Cache) Ref(binding *Binding) *Handle {
	c.mu.Lock()
	defer c.mu.Unlock()
	binding.refs++
	return &Handle{cache: c, binding: binding}
}

func (c *Cache) Commit(b *Binding) {
	c.Renew(b)
}

// renew slides the idle window. It also commits a reservation whose dial
// succeeded but whose protocol handshake is completed by the first payload
// write. A stale generation or an already expired binding is ignored: a late
// byte from an old connection must not resurrect it for new connections.
func (c *Cache) Renew(b *Binding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.isCurrentLocked(b) || c.expired(b, now) {
		return
	}
	b.committed = true
	b.lastActivity = now
}

func (c *Cache) Release(b *Binding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if b.refs > 0 {
		b.refs--
	}
	if !c.isCurrentLocked(b) {
		return
	}
	if b.refs == 0 && !c.keepLocked(b, c.now()) {
		delete(c.entries, b.key)
	}
}

func (c *Cache) isCurrentLocked(b *Binding) bool {
	current, ok := c.entries[b.key]
	return ok && current == b && current.generation == b.generation
}

// Lookup is the read-only preview used by Unwrap(metadata, false). It neither
// creates nor renews a binding.
func (c *Cache) Lookup(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	b, ok := c.entries[key]
	if !ok || !b.committed || c.expired(b, c.now()) {
		return "", false
	}
	return b.proxyName, true
}

func (c *Cache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
