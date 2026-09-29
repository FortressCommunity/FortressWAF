package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/config"
	"github.com/FortressWAF/FortressWAF/internal/sites"
	"github.com/FortressWAF/FortressWAF/internal/traincorpus"
	"github.com/gorilla/mux"
)

// maxAdminBodyBytes caps the body of any admin API request. The handlers decode
// into small structs, so a megabyte is generous; the cap prevents a huge POST
// from exhausting memory. It is enforced with MaxBytesReader so the read stops
// at the limit rather than buffering the whole body first.
const maxAdminBodyBytes = 1 << 20 // 1 MiB

// decodeJSONBody reads a bounded JSON body into v. It returns a clear error for
// an oversized body so the caller can answer 413 rather than 400.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// verifierFor builds a DNS verifier using the addresses this server expects a
// protected domain to resolve to. The list comes from server.expected_ips; when
// it is empty the verifier only checks that the domain resolves at all.
func verifierFor(cfgMgr *config.Manager) *sites.Verifier {
	return sites.NewVerifier(cfgMgr.Get().Server.ExpectedIPs)
}

// writeDecodeError answers a body-decode failure with the right status: 413 for
// an oversized body, 400 otherwise.
func writeDecodeError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) || errors.Is(err, io.ErrUnexpectedEOF) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return
	}
	if errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty request body"})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
}

// handleDomains serves the protected-domain list and the add flow.
//
//	GET  /domains   list
//	POST /domains   add {"domain":"a.com","site":"default","upstream":"http://..."}
func handleDomains(mgr *sites.Manager, cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"domains":      mgr.List(),
				"expected_ips": verifierFor(cfgMgr).ExpectedIPs(),
				"count":        len(mgr.List()),
			})
		case http.MethodPost:
			var req struct {
				Domain   string `json:"domain"`
				Site     string `json:"site"`
				Upstream string `json:"upstream"`
			}
			if err := decodeJSONBody(w, r, &req); err != nil {
				writeDecodeError(w, err)
				return
			}
			rec, err := mgr.Add(sites.DomainAdd{
				Ctx:      r.Context(),
				Domain:   req.Domain,
				SiteName: req.Site,
				Upstream: req.Upstream,
				Verify:   verifierFor(cfgMgr),
			})
			if err != nil {
				// 422 carries the verification detail so the UI can show why.
				writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
					"error":        err.Error(),
					"domain":       rec.Domain,
					"resolved_ips": rec.ResolvedIPs,
					"expected_ips": verifierFor(cfgMgr).ExpectedIPs(),
				})
				return
			}
			writeJSON(w, http.StatusCreated, rec)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}
}

// handleDomainDelete removes a domain.
func handleDomainDelete(mgr *sites.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		if err := mgr.Remove(domain); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "removed", "domain": domain})
	}
}

// handleDomainVerify re-runs DNS verification for an already-listed domain,
// without changing the config.
func handleDomainVerify(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		res := verifierFor(cfgMgr).Verify(ctx, domain)
		status := http.StatusOK
		if !res.Verified {
			status = http.StatusUnprocessableEntity
		}
		writeJSON(w, status, res)
	}
}

// handleBans serves the IP ban list.
//
//	GET  /bans   list
//	POST /bans   {"ip":"1.2.3.4","reason":"...","ttl_seconds":3600|0}
func handleBans() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			bans := globalBans.List()
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"bans":  bans,
				"count": len(bans),
			})
		case http.MethodPost:
			var req struct {
				IP         string `json:"ip"`
				Reason     string `json:"reason"`
				TTLSeconds int    `json:"ttl_seconds"`
			}
			if err := decodeJSONBody(w, r, &req); err != nil {
				writeDecodeError(w, err)
				return
			}
			if strings.TrimSpace(req.IP) == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip is required"})
				return
			}
			ttl := time.Duration(req.TTLSeconds) * time.Second
			entry, err := globalBans.Ban(req.IP, req.Reason, "operator", ttl)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusCreated, entry)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}
}

// handleBanDelete lifts a ban.
func handleBanDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := mux.Vars(r)["ip"]
		if !globalBans.Unban(ip) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "address is not banned"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "unbanned", "ip": ip})
	}
}

// handleTrainingStatus reports what the live collector has gathered. When
// collection is disabled it says so plainly rather than implying data is being
// trained on.
func handleTrainingStatus(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cfgMgr.Get()
		resp := map[string]interface{}{
			"enabled":    cfg.Training.Enabled,
			"corpus_dir": cfg.Training.CorpusDir,
		}
		if globalTrainer != nil && globalTrainer.Enabled() {
			written, dropped, unique := globalTrainer.Stats()
			resp["collected"] = written
			resp["dropped"] = dropped
			resp["unique"] = unique
			// Corpus size per category, straight from disk.
			cats := []string{
				"sql-injection", "xss", "rce", "command-injection", "ssti",
				"ldap-injection", "xxe", "deserialization", "webshell", "path-traversal",
			}
			sizes := map[string]int{}
			for _, c := range cats {
				if payloads, err := traincorpus.LoadCategory(cfg.Training.CorpusDir, c); err == nil {
					sizes[c] = len(payloads)
				}
			}
			resp["corpus_sizes"] = sizes
		} else {
			resp["note"] = "collection is disabled; set training.enabled and training.corpus_dir to gather samples"
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
