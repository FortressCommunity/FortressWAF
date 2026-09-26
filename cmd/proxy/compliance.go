package main

import (
	"net"
	"net/http"

	"github.com/FortressWAF/FortressWAF/internal/compliance"
	"github.com/FortressWAF/FortressWAF/internal/config"
	"github.com/gorilla/mux"
)

// enabledInspectors returns the detection inspector IDs actually registered
// in the engine, derived from the config flags buildEngineConfig reads.
// This is the ground truth the compliance engine verifies against, so it must
// mirror buildEngineConfig exactly - no "assume enabled" here.
func enabledInspectors(cfg *config.Config) []string {
	var ids []string
	if cfg.SQLI.Enabled {
		ids = append(ids, "sqli")
	}
	if cfg.XSS.Enabled {
		ids = append(ids, "xss")
	}
	if cfg.RCE.Enabled {
		ids = append(ids, "rce")
	}
	if cfg.DDoS.Enabled {
		ids = append(ids, "ddos")
	}
	if cfg.Protocol.Enabled {
		ids = append(ids, "protocol")
	}
	if cfg.Bot.Enabled {
		ids = append(ids, "bot")
	}
	if cfg.APIProtect.Enabled {
		ids = append(ids, "api_protect")
	}
	if cfg.Upload.Enabled {
		ids = append(ids, "upload")
	}
	if cfg.GraphQL.Enabled {
		ids = append(ids, "graphql")
	}
	if cfg.JA3.Enabled {
		ids = append(ids, "ja3")
	}
	if cfg.Desync.Enabled {
		ids = append(ids, "desync")
	}
	if cfg.ParserHardening.Enabled {
		ids = append(ids, "parser_hardening")
	}
	return ids
}

// buildComplianceInput assembles the runtime facts the compliance engine
// verifies controls against. Every field comes from a real object.
func buildComplianceInput(cfg *config.Config, auditLog *compliance.AuditLog) compliance.VerificationInput {
	protected, total := 0, 0
	for _, site := range cfg.Sites {
		total++
		if site.WAFEnabled {
			protected++
		}
	}

	return compliance.VerificationInput{
		ProtectedSites:      protected,
		TotalSites:          total,
		EnabledInspectors:   enabledInspectors(cfg),
		AdminAuthConfigured: len(cfg.Admin.APIKeys) > 0,
		TLSEnabled:          cfg.TLS.Enabled,
		TLSMinVersion:       cfg.TLS.MinVersion,
		AuditLog:            auditLog,
	}
}

func handleComplianceFrameworks(ce *compliance.ComplianceEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		frameworks := []compliance.ComplianceFramework{
			compliance.FrameworkPCI,
			compliance.FrameworkGDPR,
			compliance.FrameworkHIPAA,
			compliance.FrameworkSOC2,
		}

		out := make([]map[string]interface{}, 0, len(frameworks))
		for _, f := range frameworks {
			// Assess live so the counts reflect the running system rather
			// than whatever a previous caller left behind.
			res, err := ce.RunAssessment(f)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
					"error":  "assessment_failed",
					"detail": err.Error(),
				})
				return
			}
			out = append(out, map[string]interface{}{
				"id":                string(f),
				"compliant":         res.CompliantCount,
				"manual":            res.ManualCount,
				"total":             res.TotalCount,
				"automated":         res.AutomatedControls,
				"compliant_percent": res.CompliancePercent,
				"controls":          len(ce.GetControls(f)),
				"description":       frameworkDescription(f),
			})
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"frameworks": out,
			"note": "Controls are verified against live runtime state. " +
				"Controls that need human evidence are reported as 'manual' " +
				"and never counted as compliant.",
		})
	}
}

func frameworkDescription(f compliance.ComplianceFramework) string {
	switch f {
	case compliance.FrameworkPCI:
		return "PCI DSS - payment card industry controls"
	case compliance.FrameworkGDPR:
		return "GDPR - EU data protection controls"
	case compliance.FrameworkHIPAA:
		return "HIPAA - US health information controls"
	case compliance.FrameworkSOC2:
		return "SOC 2 - service organisation controls"
	default:
		return string(f)
	}
}

func handleComplianceAssessment(ce *compliance.ComplianceEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		framework := compliance.ComplianceFramework(vars["framework"])

		switch framework {
		case compliance.FrameworkPCI, compliance.FrameworkGDPR,
			compliance.FrameworkHIPAA, compliance.FrameworkSOC2:
		default:
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":  "unknown_framework",
				"detail": "supported frameworks: pci-dss, gdpr, hipaa, soc2",
			})
			return
		}

		result, err := ce.RunAssessment(framework)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":  "assessment_failed",
				"detail": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}

func handleAuditLog(al *compliance.AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("action")

		filter := compliance.AuditFilter{}
		if action != "" {
			filter.Action = action
		}

		entries, err := al.Query(filter)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":  "audit_query_failed",
				"detail": err.Error(),
			})
			return
		}

		valid, err := al.VerifyIntegrity()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"total":   al.Len(),
			"entries": entries,
			"integrity": map[string]interface{}{
				"valid": valid,
				"error": errString(err),
			},
		})
	}
}

// clientIP returns the requesting peer's address without the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
