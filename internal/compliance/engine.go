// Package compliance maps the WAF's actual runtime state onto control
// frameworks (PCI DSS, GDPR, HIPAA, SOC 2).
//
// This is a *verification* engine, not a policy engine. checkControl() only
// ever reports "compliant" for a control it can genuinely observe in the
// running system - an enabled inspector, a protected site, a written audit
// entry. Controls that depend on human or organisational evidence (policies,
// breach-notification procedures, DPIAs) are reported as "manual" with the
// reason, rather than being stamped compliant to look good in a report.
package compliance

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

type ComplianceFramework string

const (
	FrameworkPCI    ComplianceFramework = "pci-dss"
	FrameworkGDPR   ComplianceFramework = "gdpr"
	FrameworkHIPAA  ComplianceFramework = "hipaa"
	FrameworkSOC2   ComplianceFramework = "soc2"
	FrameworkISO27K ComplianceFramework = "iso-27001"
)

// Control status values.
const (
	StatusCompliant    = "compliant"     // verified automatically against runtime state
	StatusNonCompliant = "non_compliant" // checked and failed; see Remediation
	StatusManual       = "manual"        // cannot be verified automatically; needs human evidence
)

type Control struct {
	ID          string              `json:"id"`
	Framework   ComplianceFramework `json:"framework"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Status      string              `json:"status"`
	LastChecked time.Time           `json:"last_checked"`
	Evidence    []Evidence          `json:"evidence"`
	Remediation string              `json:"remediation,omitempty"`
}

type Evidence struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	CollectedAt time.Time `json:"collected_at"`
	Source      string    `json:"source"`
	Data        string    `json:"data,omitempty"`
}

// VerificationInput carries the runtime facts the engine verifies controls
// against. The caller (cmd/proxy) must populate every field from real
// objects - config, engine, metrics, audit log - never from defaults or
// guesses, otherwise the evidence below is worthless.
type VerificationInput struct {
	// Sites with WAF protection enabled, and the total number of sites.
	ProtectedSites int
	TotalSites     int

	// Inspector IDs registered in the detection engine, e.g. "sqli".
	EnabledInspectors []string

	// True when the admin API requires a configured API key to log in.
	AdminAuthConfigured bool

	// TLS settings actually in effect for the proxy listener.
	TLSEnabled    bool
	TLSMinVersion string

	// Audit trail. Nil means no audit log is attached. The engine reads it
	// live at assessment time, so counts and chain status are never stale.
	AuditLog *AuditLog
}

type ComplianceEngine struct {
	mu       sync.RWMutex
	controls map[ComplianceFramework][]Control
	input    VerificationInput
}

func NewComplianceEngine(input VerificationInput) *ComplianceEngine {
	ce := &ComplianceEngine{
		controls: make(map[ComplianceFramework][]Control),
		input:    input,
	}
	ce.initControls()
	return ce
}

func (ce *ComplianceEngine) initControls() {
	ce.controls[FrameworkPCI] = ce.getPCIControls()
	ce.controls[FrameworkGDPR] = ce.getGDPRControls()
	ce.controls[FrameworkSOC2] = ce.getSOC2Controls()
	ce.controls[FrameworkHIPAA] = ce.getHIPAAControls()
}

func (ce *ComplianceEngine) GetControls(framework ComplianceFramework) []Control {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.controls[framework]
}

// GetComplianceStatus returns how many controls are auto-verified as
// compliant out of the framework total. Controls needing manual evidence are
// counted separately and never inflate the compliant figure.
func (ce *ComplianceEngine) GetComplianceStatus(framework ComplianceFramework) (compliant, manual, total int) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	for _, ctrl := range ce.controls[framework] {
		total++
		switch ctrl.Status {
		case StatusCompliant:
			compliant++
		case StatusManual:
			manual++
		}
	}
	return
}

func (ce *ComplianceEngine) RunAssessment(framework ComplianceFramework) (*AssessmentResult, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	result := &AssessmentResult{
		Framework:  framework,
		AssessedAt: time.Now(),
		Controls:   []Control{},
	}

	for i := range ce.controls[framework] {
		ctrl := &ce.controls[framework][i]
		ctrl.LastChecked = time.Now()
		ctrl.Evidence = ctrl.Evidence[:0]

		ce.checkControl(ctrl)

		result.Controls = append(result.Controls, *ctrl)
		switch ctrl.Status {
		case StatusCompliant:
			result.CompliantCount++
		case StatusManual:
			result.ManualCount++
		}
		result.TotalCount++
	}

	// Only verified controls count towards the percentage.
	verified := result.TotalCount - result.ManualCount
	if verified > 0 {
		result.CompliancePercent = float64(result.CompliantCount) / float64(verified) * 100
	}
	result.AutomatedControls = verified

	return result, nil
}

type AssessmentResult struct {
	Framework         ComplianceFramework `json:"framework"`
	AssessedAt        time.Time           `json:"assessed_at"`
	CompliantCount    int                 `json:"compliant_count"`
	ManualCount       int                 `json:"manual_count"`
	TotalCount        int                 `json:"total_count"`
	AutomatedControls int                 `json:"automated_controls"` // controls the engine can verify
	CompliancePercent float64             `json:"compliance_percent"` // of the automated controls
	Controls          []Control           `json:"controls"`
}

// hasInspector reports whether an inspector with the given config key
// ("sqli", "xss", ...) is registered in the engine.
func (ce *ComplianceEngine) hasInspector(id string) bool {
	return slices.Contains(ce.input.EnabledInspectors, id)
}

// checkControl verifies one control against the runtime input. Anything not
// handled here is deliberately reported as StatusManual.
func (ce *ComplianceEngine) checkControl(ctrl *Control) {
	now := time.Now()
	pass := func(source, description string, data string) {
		ctrl.Status = StatusCompliant
		ctrl.Remediation = ""
		ctrl.Evidence = append(ctrl.Evidence, Evidence{
			Type:        "observation",
			Description: description,
			CollectedAt: now,
			Source:      source,
			Data:        data,
		})
	}
	fail := func(remediation, observation string) {
		ctrl.Status = StatusNonCompliant
		ctrl.Remediation = remediation
		ctrl.Evidence = append(ctrl.Evidence, Evidence{
			Type:        "observation",
			Description: observation,
			CollectedAt: now,
			Source:      "fortresswaf:runtime",
		})
	}

	switch ctrl.ID {
	// --- PCI DSS: WAF deployment and attack coverage --------------------
	case "PCI-6.4", "PCI-6.6":
		// "Public-facing web applications are protected by a WAF."
		if ce.input.TotalSites == 0 {
			fail("configure at least one site with waf_enabled: true",
				"no sites are configured, so nothing is protected")
			return
		}
		if ce.input.ProtectedSites == 0 {
			fail(fmt.Sprintf("set waf_enabled: true on the %d configured site(s)", ce.input.TotalSites),
				fmt.Sprintf("0 of %d configured sites have WAF protection enabled", ce.input.TotalSites))
			return
		}
		pass("fortresswaf:config:sites",
			"WAF enforcement is active on the configured upstream sites",
			fmt.Sprintf("%d of %d sites have waf_enabled: true", ce.input.ProtectedSites, ce.input.TotalSites))

	case "PCI-6.5.1":
		if !ce.hasInspector("sqli") {
			fail("enable the sqli inspector (sqli.enabled: true in config)",
				"the SQL injection inspector is not registered in the engine")
			return
		}
		pass("fortresswaf:engine:inspectors",
			"SQL injection inspector registered and blocking",
			"inspector=sqli")

	case "PCI-6.5.2":
		if !ce.hasInspector("xss") {
			fail("enable the xss inspector (xss.enabled: true in config)",
				"the cross-site scripting inspector is not registered in the engine")
			return
		}
		pass("fortresswaf:engine:inspectors",
			"XSS inspector registered and blocking",
			"inspector=xss")

	case "PCI-6.5.9":
		if !ce.hasInspector("rce") {
			fail("enable the rce inspector (rce.enabled: true in config)",
				"the OS command injection inspector is not registered in the engine")
			return
		}
		pass("fortresswaf:engine:inspectors",
			"OS command injection inspector registered and blocking",
			"inspector=rce")

	case "PCI-6.5.8":
		if !ce.hasInspector("upload") {
			fail("enable the upload inspector (upload.enabled: true in config)",
				"the file upload inspector is not registered in the engine")
			return
		}
		pass("fortresswaf:engine:inspectors",
			"Uploaded files are validated by the upload inspector",
			"inspector=upload")

	// --- PCI DSS: authentication ----------------------------------------
	case "PCI-8.2", "SOC2-CC6.1", "SOC2-CC6.3":
		if !ce.input.AdminAuthConfigured {
			fail("configure admin.api_keys so the admin API requires authentication",
				"no admin API keys are configured: the admin API is open")
			return
		}
		pass("fortresswaf:config:admin",
			"Access to the admin API requires a configured credential",
			"admin.api_keys configured")

	// --- PCI DSS / SOC 2 / HIPAA: audit trail ---------------------------
	case "PCI-10.1", "PCI-10.2", "PCI-10.3", "SOC2-CC6.6",
		"HIPAA-164.310(b)", "HIPAA-164.312(b)":
		if ce.input.AuditLog == nil {
			fail("attach an audit log so security events are recorded",
				"no audit log is attached to the compliance engine")
			return
		}
		count := ce.input.AuditLog.Len()
		if count == 0 {
			fail("generate traffic or run an attack test so the audit log records at least one security event",
				"the audit log is attached but contains no entries yet")
			return
		}
		if valid, err := ce.input.AuditLog.VerifyIntegrity(); err != nil || !valid {
			fail("investigate and restore the audit log: hash chain verification failed",
				"audit log hash chain verification FAILED - entries may have been tampered with")
			return
		}
		pass("fortresswaf:audit:log",
			"Security events are written to a hash-chained audit trail",
			fmt.Sprintf("%d entries, chain integrity verified", count))

	// --- GDPR / SOC 2: transport encryption -----------------------------
	case "GDPR-Art32", "GDPR-Art32-1-C", "GDPR-Art5-1-F",
		"SOC2-CC9.1", "HIPAA-164.310(d)", "HIPAA-164.312(e)":
		if !ce.input.TLSEnabled {
			fail("enable TLS on the proxy listener (tls.enabled: true plus cert_file/key_file)",
				"TLS is disabled on the proxy listener: traffic is sent in cleartext")
			return
		}
		pass("fortresswaf:config:tls",
			"TLS is enabled for the proxy listener",
			fmt.Sprintf("min_version=%s", ce.input.TLSMinVersion))

	// --- SOC 2: monitoring ----------------------------------------------
	case "SOC2-CC7.2":
		auditCount := 0
		if ce.input.AuditLog != nil {
			auditCount = ce.input.AuditLog.Len()
		}
		if ce.input.ProtectedSites == 0 || auditCount == 0 {
			fail("enable WAF protection and generate security events so monitoring has something to observe",
				fmt.Sprintf("protected_sites=%d audit_entries=%d", ce.input.ProtectedSites, auditCount))
			return
		}
		pass("fortresswaf:monitoring",
			"Detection engine and audit trail are active and recording security events",
			fmt.Sprintf("protected_sites=%d audit_entries=%d", ce.input.ProtectedSites, auditCount))

	default:
		// Anything not handled above depends on processes, policies or
		// documentation that lives outside this software. Saying "compliant"
		// here would be a lie, so we ask for human evidence instead.
		ctrl.Status = StatusManual
		ctrl.Remediation = "Requires evidence outside the software: " +
			strings.ToLower(ctrl.Description) +
			". Collect the supporting documentation and attach it to the control record."
		ctrl.Evidence = nil
	}
}

func (ce *ComplianceEngine) ExportReport(framework ComplianceFramework, format string) ([]byte, error) {
	result, err := ce.RunAssessment(framework)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return ce.exportJSON(result)
	case "pdf":
		return ce.exportPDF(result)
	case "csv":
		return ce.exportCSV(result)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func (ce *ComplianceEngine) exportJSON(r *AssessmentResult) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"framework":"%s","assessed_at":"%s","compliant":%d,"manual":%d,"total":%d,"automated":%d,"percent":%.2f}`,
		r.Framework, r.AssessedAt.Format(time.RFC3339),
		r.CompliantCount, r.ManualCount, r.TotalCount, r.AutomatedControls, r.CompliancePercent)), nil
}

func (ce *ComplianceEngine) exportPDF(r *AssessmentResult) ([]byte, error) {
	return []byte(fmt.Sprintf("Compliance Report: %s\nAssessed: %s\nCompliant: %d/%d automated controls (%.1f%%), %d require manual evidence",
		r.Framework, r.AssessedAt.Format("2006-01-02"),
		r.CompliantCount, r.AutomatedControls, r.CompliancePercent, r.ManualCount)), nil
}

func (ce *ComplianceEngine) exportCSV(r *AssessmentResult) ([]byte, error) {
	var b strings.Builder
	b.WriteString("ControlID,Framework,Status,LastChecked\n")
	for _, c := range r.Controls {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%s\n",
			c.ID, c.Framework, c.Status, c.LastChecked.Format(time.RFC3339)))
	}
	return []byte(b.String()), nil
}
