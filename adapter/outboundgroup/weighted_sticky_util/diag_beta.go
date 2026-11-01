//go:build beta_diag

package weightedsticky

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	diagQueueSize       = 1024
	diagSummaryInterval = time.Minute
)

type diagInstance struct {
	group  string
	totals map[string]map[string]uint64
}

// fileDiag is the process-wide beta writer. It is created during strategy
// construction but opens no file and starts no goroutine until Start registers
// the first running strategy. Hot reload reuses the same writer and file.
type fileDiag struct {
	runID string
	key   []byte

	ch     chan diagEvent
	active atomic.Bool

	mu        sync.Mutex
	file      *os.File
	instances map[string]*diagInstance
	started   bool

	writeMu sync.Mutex

	dropped     atomic.Uint64
	writeErrors atomic.Uint64
}

var (
	processDiagMu sync.Mutex
	processDiag   diagEmitter
)

func newProcessDiag() diagEmitter {
	processDiagMu.Lock()
	defer processDiagMu.Unlock()
	if processDiag == nil {
		writer, err := newFileDiag()
		if err != nil {
			log.Errorln("weighted-sticky diag: cannot create random IDs: %v", err)
			processDiag = noopDiag{}
		} else {
			processDiag = writer
		}
	}
	return processDiag
}

func newFileDiag() (*fileDiag, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	runID, err := newRunID()
	if err != nil {
		return nil, err
	}
	return &fileDiag{
		runID:     runID,
		key:       key,
		instances: map[string]*diagInstance{},
	}, nil
}

func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (d *fileDiag) Enabled() bool { return d.active.Load() }

func (d *fileDiag) KeyID(key string) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, d.key)
	_, _ = mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func (d *fileDiag) Register(instance, group string, config diagConfig) {
	d.mu.Lock()
	if _, exists := d.instances[instance]; exists {
		d.mu.Unlock()
		return
	}
	if !d.started {
		if err := d.openLocked(); err != nil {
			d.mu.Unlock()
			log.Errorln("weighted-sticky diag: cannot open output: %v", err)
			return
		}
	}
	d.instances[instance] = &diagInstance{
		group:  group,
		totals: map[string]map[string]uint64{},
	}
	d.mu.Unlock()

	d.Emit(diagEvent{
		Name:     "strategy.start",
		Group:    group,
		Instance: instance,
		Fields:   config.fields(),
	})
}

func (d *fileDiag) Unregister(instance string) {
	d.mu.Lock()
	inst := d.instances[instance]
	if inst == nil {
		d.mu.Unlock()
		return
	}
	delete(d.instances, instance)
	event := diagEvent{
		Name:     "summary",
		Group:    inst.group,
		Instance: instance,
		Fields: map[string]any{
			"final":        true,
			"totals":       copyTotals(inst.totals),
			"dropped":      d.dropped.Load(),
			"write_errors": d.writeErrors.Load(),
			"interval_ms":  int64(diagSummaryInterval / time.Millisecond),
		},
	}
	d.mu.Unlock()

	// Close waits for events already queued for this instance to reach the file.
	event.flushed = make(chan struct{})
	d.ch <- event
	<-event.flushed
}

func (d *fileDiag) Emit(event diagEvent) {
	if !d.active.Load() {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	ch := d.ch
	select {
	case ch <- event:
	default:
		n := d.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			log.Warnln("weighted-sticky diag: dropped %d events", n)
		}
	}
}

func (d *fileDiag) AddCount(instance, node, metric string, n uint64) {
	if n == 0 || node == "" || metric == "" || !d.active.Load() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	inst := d.instances[instance]
	if inst == nil {
		return
	}
	counts := inst.totals[node]
	if counts == nil {
		counts = map[string]uint64{}
		inst.totals[node] = counts
	}
	counts[metric] += n
}

func (d *fileDiag) openLocked() error {
	home := C.Path.HomeDir()
	if home == "" {
		return errors.New("empty home directory")
	}
	dir := filepath.Join(home, "diagnostics", "weighted-sticky")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("weighted-sticky-%s-%d-%s.ndjson",
		time.Now().UTC().Format("20060102T150405Z"), os.Getpid(), d.runID)
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	d.file = file
	d.ch = make(chan diagEvent, diagQueueSize)
	d.started = true

	d.writeMarshaled(diagEvent{
		Name: "run.start",
		Fields: map[string]any{
			"version":    C.Version,
			"pid":        os.Getpid(),
			"started_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	go d.run()
	go d.runSummary()
	d.active.Store(true)
	log.Infoln("weighted-sticky diag: writing diagnostics/weighted-sticky/%s", name)
	return nil
}

func (d *fileDiag) run() {
	for event := range d.ch {
		if event.Name == "summary" && event.flushed != nil {
			event.Fields["dropped"] = d.dropped.Load()
			event.Fields["write_errors"] = d.writeErrors.Load()
		}
		d.writeMarshaled(event)
		if event.flushed != nil {
			close(event.flushed)
		}
	}
}

func (d *fileDiag) runSummary() {
	ticker := time.NewTicker(diagSummaryInterval)
	defer ticker.Stop()
	for range ticker.C {
		d.emitSummaries()
	}
}

func (d *fileDiag) emitSummaries() {
	d.mu.Lock()
	instances := make([]string, 0, len(d.instances))
	for instance := range d.instances {
		instances = append(instances, instance)
	}
	sort.Strings(instances)
	events := make([]diagEvent, 0, len(instances))
	for _, instance := range instances {
		inst := d.instances[instance]
		events = append(events, diagEvent{
			Name:     "summary",
			Group:    inst.group,
			Instance: instance,
			Fields: map[string]any{
				"final":        false,
				"totals":       copyTotals(inst.totals),
				"dropped":      d.dropped.Load(),
				"write_errors": d.writeErrors.Load(),
				"interval_ms":  int64(diagSummaryInterval / time.Millisecond),
			},
		})
	}
	d.mu.Unlock()

	for _, event := range events {
		d.Emit(event)
	}
}

func (d *fileDiag) writeMarshaled(event diagEvent) {
	line := d.line(event)
	encoded, err := json.Marshal(line)
	if err != nil {
		d.writeErrors.Add(1)
		log.Errorln("weighted-sticky diag: encode failed: %v", err)
		return
	}
	d.writeLine(encoded)
}

func (d *fileDiag) line(event diagEvent) map[string]any {
	ts := event.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	line := map[string]any{
		"ts":    ts.UTC().Format(time.RFC3339Nano),
		"run":   d.runID,
		"event": event.Name,
	}
	if event.Group != "" {
		line["group"] = event.Group
	}
	if event.Instance != "" {
		line["instance"] = event.Instance
	}
	if event.Flow != "" {
		line["flow"] = event.Flow
	}
	if len(event.Fields) != 0 {
		line["fields"] = event.Fields
	}
	return line
}

func (d *fileDiag) writeLine(line []byte) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.file == nil {
		return
	}
	line = append(line, '\n')
	if _, err := d.file.Write(line); err != nil {
		n := d.writeErrors.Add(1)
		if n == 1 || n%100 == 0 {
			log.Errorln("weighted-sticky diag: write failed: %v", err)
		}
	}
}

func copyTotals(src map[string]map[string]uint64) map[string]map[string]uint64 {
	dst := make(map[string]map[string]uint64, len(src))
	for node, metrics := range src {
		copied := make(map[string]uint64, len(metrics))
		for metric, value := range metrics {
			copied[metric] = value
		}
		dst[node] = copied
	}
	return dst
}
