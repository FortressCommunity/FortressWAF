package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/compliance"
	"github.com/FortressWAF/FortressWAF/internal/config"
	"github.com/FortressWAF/FortressWAF/internal/engine"
	"github.com/gorilla/mux"
)

// This file adds the operator-facing endpoints the dashboard needs beyond the
// original status/config/sites/rules set: a metrics snapshot, a threat
// analytics summary, an alert inbox, a recent-traffic view, and per-inspector
// detail. Each is derived from data the WAF already holds (the audit log and
// the atomic counters), so nothing here invents numbers.

// ---------------------------------------------------------------------------
// Alert store
// ---------------------------------------------------------------------------

// alert is an operator-facing notification. The WAF creates them from security
// events (a burst of blocks, a new attacker, a tamper check failure); an
// operator acknowledges them so the inbox reflects what has been triaged.
type alert struct {
	ID           string     `json:"id"`
	CreatedAt    time.Time  `json:"created_at"`
	Severity     string     `json:"severity"` // critical | high | medium | low
	Title        string     `json:"title"`
	Detail       string     `json:"detail"`
	Source       string     `json:"source"` // rule id or component
	Acknowledged bool       `json:"acknowledged"`
	AckedBy      string     `json:"acked_by,omitempty"`
	AckedAt      *time.Time `json:"acked_at,omitempty"`
}

// alertStore is a bounded, in-memory alert inbox. It keeps the newest maxAlerts
// entries; older ones are dropped so a long-running demo cannot grow without
// bound.
type alertStore struct {
	mu      sync.RWMutex
	alerts  []alert
	seq     uint64
	maxSize int
}

func newAlertStore(maxSize int) *alertStore {
	if maxSize <= 0 {
		maxSize = 500
	}
	return &alertStore{alerts: make([]alert, 0, maxSize), maxSize: maxSize}
}

func (s *alertStore) add(severity, title, detail, source string) alert {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Deduplicate an identical title+source that arrived in the last minute, so
	// a burst of the same event does not fill the inbox.
	cutoff := time.Now().Add(-time.Minute)
	for i := range s.alerts {
		a := &s.alerts[i]
		if a.Title == title && a.Source == source && a.CreatedAt.After(cutoff) {
			a.Detail = detail
			a.CreatedAt = time.Now()
			return *a
		}
	}

	s.seq++
	a := alert{
		ID:        fmt.Sprintf("ALR-%06d", s.seq),
		CreatedAt: time.Now(),
		Severity:  severity,
		Title:     title,
		Detail:    detail,
		Source:    source,
	}
	s.alerts = append(s.alerts, a)
	if len(s.alerts) > s.maxSize {
		s.alerts = s.alerts[len(s.alerts)-s.maxSize:]
	}
	return a
}

func (s *alertStore) list() []alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]alert, len(s.alerts))
	copy(out, s.alerts)
	// Newest first.
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *alertStore) ack(id, who string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.alerts {
		if s.alerts[i].ID == id {
			now := time.Now()
			s.alerts[i].Acknowledged = true
			s.alerts[i].AckedBy = who
			s.alerts[i].AckedAt = &now
			return true
		}
	}
	return false
}

func (s *alertStore) remove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.alerts {
		if s.alerts[i].ID == id {
			s.alerts = append(s.alerts[:i], s.alerts[i+1:]...)
			return true
		}
	}
	return false
}

func (s *alertStore) stats() (total, unacked int, bySeverity map[string]int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bySeverity = map[string]int{}
	for _, a := range s.alerts {
		total++
		bySeverity[a.Severity]++
		if !a.Acknowledged {
			unacked++
		}
	}
	return
}

// serverAlerts is the process-wide alert inbox. It is created once so the
// handlers and the WAF event path share the same instance.
var serverAlerts = newAlertStore(500)

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleMetricsSnapshot returns the counters the dashboard displays, as JSON.
// The text /metrics endpoint is for Prometheus; this is the same data shaped
// for the console.
func handleMetricsSnapshot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uptime := time.Since(startedAt)
		secs := uptime.Seconds()
		rps := 0.0
		if secs > 0 {
			rps = float64(totalRequests.Load()) / secs
		}
		total := totalRequests.Load()
		blocked := blockedRequests.Load()
		blockRate := 0.0
		if total > 0 {
			blockRate = float64(blocked) / float64(total) * 100
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"uptime_seconds":        int(secs),
			"requests_total":        total,
			"requests_blocked":      blocked,
			"requests_allowed":      allowedRequests.Load(),
			"requests_excluded":     excludedRequests.Load(),
			"requests_challenged":   challengedReqs.Load(),
			"requests_rate_limited": rateLimitedReqs.Load(),
			"requests_monitored":    monitoredReqs.Load(),
			"active_connections":    activeConns.Load(),
			"requests_per_second":   rps,
			"block_rate_percent":    blockRate,
		})
	}
}

// handleAnalytics summarises the audit log into the shapes the analytics page
// needs: a time series of blocks, top attacker IPs, top rule families, and the
// method/result mix.
func handleAnalytics(al *compliance.AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := al.Query(compliance.AuditFilter{})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "audit_query_failed"})
			return
		}

		const buckets = 30
		now := time.Now()
		series := make([]map[string]interface{}, buckets)
		counts := make([]int, buckets)
		for i := 0; i < buckets; i++ {
			ts := now.Add(-time.Duration(buckets-1-i) * time.Minute)
			series[i] = map[string]interface{}{"minute": ts.Format("15:04"), "count": 0}
		}

		byIP := map[string]int{}
		byRule := map[string]int{}
		byAction := map[string]int{}
		byResult := map[string]int{}

		for _, e := range entries {
			age := now.Sub(e.Timestamp)
			idx := buckets - 1 - int(age.Minutes())
			if idx >= 0 && idx < buckets {
				counts[idx]++
			}
			ip := e.ActorIP
			if ip == "" {
				ip = "unknown"
			}
			byIP[ip]++
			rule := e.Metadata
			if i := strings.Index(rule, ":"); i > 0 {
				rule = rule[:i]
			}
			if rule == "" {
				rule = e.Action
			}
			byRule[rule]++
			byAction[e.Action]++
			byResult[e.Result]++
		}
		for i := range series {
			series[i]["count"] = counts[i]
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"total_events":  len(entries),
			"series":        series,
			"top_attackers": topN(byIP, 8, "ip", "count"),
			"top_rules":     topN(byRule, 8, "rule", "count"),
			"by_action":     mapToSorted(byAction, "action"),
			"by_result":     mapToSorted(byResult, "result"),
		})
	}
}

// handleTrafficLog returns the most recent audit entries as a flat, filterable
// list for the traffic page. Filters: q (substring over resource/ip/metadata),
// action, limit.
func handleTrafficLog(al *compliance.AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := al.Query(compliance.AuditFilter{})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "audit_query_failed"})
			return
		}

		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		action := r.URL.Query().Get("action")
		limit := 200

		out := make([]compliance.AuditEntry, 0, len(entries))
		// Newest first.
		for i := len(entries) - 1; i >= 0; i-- {
			e := entries[i]
			if action != "" && e.Action != action {
				continue
			}
			if q != "" {
				hay := strings.ToLower(e.Resource + " " + e.ActorIP + " " + e.Metadata + " " + e.Action)
				if !strings.Contains(hay, q) {
					continue
				}
			}
			out = append(out, e)
			if len(out) >= limit {
				break
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"total":   al.Len(),
			"count":   len(out),
			"entries": out,
		})
	}
}

// handleInspectorDetail returns one inspector's definition plus its recent
// hits, so the dashboard can show what a module does and what it has caught.
func handleInspectorDetail(e *engine.Engine, al *compliance.AuditLog) http.HandlerFunc {
	// Rule-id prefixes by inspector name, mirroring handleListInspectors.
	prefixes := map[string]string{
		"sqli": "SQLI", "xss": "XSS", "rce": "RCE", "ddos_protection": "DDoS",
		"protocol_anomaly": "PROT", "bot_detector": "BOT", "api_protection": "API",
		"file_upload": "UPL", "ja3": "JA3", "desync": "DSYNC",
		"parser_hardener": "PARSER_", "credential_protection": "CRED",
		"response_inspect": "LEAK",
	}
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		entries, err := al.Query(compliance.AuditFilter{})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "audit_query_failed"})
			return
		}

		prefix := prefixes[name]
		recent := make([]compliance.AuditEntry, 0, 20)
		hits := 0
		for i := len(entries) - 1; i >= 0; i-- {
			meta := entries[i].Metadata
			if prefix == "" || strings.HasPrefix(meta, prefix) {
				hits++
				if len(recent) < 20 {
					recent = append(recent, entries[i])
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"name":        name,
			"rule_prefix": prefix,
			"hits":        hits,
			"recent":      recent,
		})
	}
}

// handleAlerts serves the alert inbox.
//
//	GET    /alerts            list all
//	POST   /alerts            create one (for testing/demo)
//	POST   /alerts/{id}/ack   acknowledge
//	DELETE /alerts/{id}       remove
func handleAlerts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			total, unacked, bySeverity := serverAlerts.stats()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"total":       total,
				"unacked":     unacked,
				"by_severity": bySeverity,
				"alerts":      serverAlerts.list(),
			})
		case http.MethodPost:
			var req struct {
				Severity string `json:"severity"`
				Title    string `json:"title"`
				Detail   string `json:"detail"`
				Source   string `json:"source"`
			}
			if err := decodeJSONBody(w, r, &req); err != nil {
				writeDecodeError(w, err)
				return
			}
			if req.Title == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title is required"})
				return
			}
			if req.Severity == "" {
				req.Severity = "medium"
			}
			a := serverAlerts.add(req.Severity, req.Title, req.Detail, req.Source)
			writeJSON(w, http.StatusCreated, a)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}
}

// handleAlertByID handles acknowledge and delete for a single alert.
func handleAlertByID(who func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ack"):
			if serverAlerts.ack(id, who(r)) {
				writeJSON(w, http.StatusOK, map[string]interface{}{"status": "acknowledged", "id": id})
			} else {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			}
		case r.Method == http.MethodDelete:
			if serverAlerts.remove(id) {
				writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "id": id})
			} else {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			}
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}
}

// handleConfigDetail returns the resolved configuration the console can show
// without leaking secrets: sites, enabled modules, and feature flags.
func handleConfigDetail(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cfgMgr.Get()
		modules := map[string]bool{
			"sqli": cfg.SQLI.Enabled, "xss": cfg.XSS.Enabled, "rce": cfg.RCE.Enabled,
			"ddos": cfg.DDoS.Enabled, "protocol": cfg.Protocol.Enabled, "bot": cfg.Bot.Enabled,
			"api_protect": cfg.APIProtect.Enabled, "upload": cfg.Upload.Enabled,
			"credential": cfg.Credential.Enabled, "desync": cfg.Desync.Enabled,
			"parser_hardening": cfg.ParserHardening.Enabled,
			"response_inspect": cfg.RespInspect.Enabled,
			"wasm":             cfg.WASM.Enabled, "ebpf": cfg.EBPF.Enabled, "ml": cfg.ML.Enabled,
		}
		enabled := make([]string, 0, len(modules))
		for name, on := range modules {
			if on {
				enabled = append(enabled, name)
			}
		}
		sort.Strings(enabled)

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"version":                 Version,
			"commit":                  Commit,
			"build_date":              BuildDate,
			"sites_count":             len(cfg.Sites),
			"rules_count":             len(cfg.Rules),
			"enabled_modules":         enabled,
			"modules":                 modules,
			"response_inspect_blocks": cfg.RespInspect.Block,
			"tls_enabled":             cfg.TLS.Enabled,
			"shadow_mode":             cfg.ShadowMode.Enabled,
			"learning_mode":           cfg.LearningMode.Enabled,
			"prometheus":              cfg.Prometheus.Enabled,
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func topN(counts map[string]int, n int, keyName, valName string) []map[string]interface{} {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(counts))
	for k, v := range counts {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	if len(items) > n {
		items = items[:n]
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]interface{}{keyName: it.k, valName: it.v})
	}
	return out
}

func mapToSorted(counts map[string]int, keyName string) []map[string]interface{} {
	return topN(counts, len(counts), keyName, "count")
}
