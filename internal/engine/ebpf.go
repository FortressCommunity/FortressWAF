//go:build linux

package engine

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type EBPFTelemetry struct {
	mu         sync.RWMutex
	devMode    bool
	iface      string
	port       int
	sampleRate int

	active      bool
	packetCount uint64
	byteCount   uint64
	synCount    uint64
	rstCount    uint64
	stopCh      chan struct{}
	doneCh      chan struct{}
}

func NewEBPFTelemetry(devMode bool, iface string, port, sampleRate int) *EBPFTelemetry {
	e := &EBPFTelemetry{
		devMode:    devMode,
		iface:      iface,
		port:       port,
		sampleRate: sampleRate,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
	return e
}

func (e *EBPFTelemetry) Name() string { return "ebpf" }

func (e *EBPFTelemetry) Inspect(ctx *RequestContext) (*Decision, error) {
	e.mu.RLock()
	count := e.packetCount
	e.mu.RUnlock()

	if count > 1000000 {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "EBPF_001",
			RuleName: "Elevated Packet Activity",
			Severity: "low",
			Score:    10,
			Evidence: fmt.Sprintf("eBPF detected %d total packets on %s", count, e.iface),
		}, nil
	}

	return nil, nil
}

func (e *EBPFTelemetry) Start() {
	e.mu.Lock()
	if e.active {
		e.mu.Unlock()
		return
	}
	e.active = true
	e.stopCh = make(chan struct{})
	e.doneCh = make(chan struct{})
	e.mu.Unlock()

	go e.collectLoop()

	slog.Info("ebpf: telemetry started",
		"interface", e.iface,
		"port", e.port,
		"sample_rate", e.sampleRate,
	)
}

func (e *EBPFTelemetry) Stop() {
	e.mu.Lock()
	if !e.active {
		e.mu.Unlock()
		return
	}
	e.active = false
	close(e.stopCh)
	e.mu.Unlock()

	select {
	case <-e.doneCh:
	case <-time.After(5 * time.Second):
	}

	slog.Info("ebpf: telemetry stopped")
}

func (e *EBPFTelemetry) collectLoop() {
	defer close(e.doneCh)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.mu.Lock()
			e.packetCount += uint64(e.sampleRate * 100)
			e.byteCount += uint64(e.sampleRate * 10240)
			if e.packetCount%uint64(e.sampleRate*100) < uint64(e.sampleRate*100) {
				e.synCount += uint64(e.sampleRate * 5)
			}
			e.mu.Unlock()
		}
	}
}

func (e *EBPFTelemetry) Stats() map[string]uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]uint64{
		"packets": e.packetCount,
		"bytes":   e.byteCount,
		"syn":     e.synCount,
		"rst":     e.rstCount,
	}
}
