package compliance

import (
	"encoding/json"
	"strings"
	"testing"
)

func auditLogWith(t *testing.T, n int) *AuditLog {
	t.Helper()
	al := NewAuditLog()
	for i := 0; i < n; i++ {
		if err := al.Append(AuditEntry{
			ActorID: "admin", ActorType: "user", ActorIP: "127.0.0.1",
			Action: "block", Resource: "proxy", Result: "blocked",
		}); err != nil {
			t.Fatalf("audit append: %v", err)
		}
	}
	return al
}

func fullInput(t *testing.T) VerificationInput {
	t.Helper()
	return VerificationInput{
		ProtectedSites:      2,
		TotalSites:          2,
		EnabledInspectors:   []string{"sqli", "xss", "rce", "upload"},
		AdminAuthConfigured: true,
		TLSEnabled:          true,
		TLSMinVersion:       "1.2",
		AuditLog:            auditLogWith(t, 5),
	}
}

// tamperedLog builds a valid chain then forges one entry's content, so
// VerifyIntegrity must fail when it recomputes hashes.
func tamperedLog(t *testing.T) *AuditLog {
	t.Helper()
	al := auditLogWith(t, 3)
	al.mu.Lock()
	al.entries[1].Action = "forged"
	al.mu.Unlock()
	return al
}

// The old engine hard-coded "compliant" for every control it recognised.
// Now a control may only be compliant when its runtime precondition holds.
func TestRunAssessment_CompliantWhenConfigured(t *testing.T) {
	ce := NewComplianceEngine(fullInput(t))

	res, err := ce.RunAssessment(FrameworkPCI)
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if res.TotalCount == 0 {
		t.Fatal("expected PCI controls to be defined")
	}
	if res.CompliantCount == 0 {
		t.Fatalf("expected some controls to be verified compliant, got %+v", res)
	}
	if res.ManualCount == 0 {
		t.Fatal("expected some controls to need manual evidence")
	}
	if res.AutomatedControls != res.TotalCount-res.ManualCount {
		t.Fatalf("automated controls miscounted: %d vs %d-%d",
			res.AutomatedControls, res.TotalCount, res.ManualCount)
	}
	for _, c := range res.Controls {
		if c.Status == StatusCompliant && len(c.Evidence) == 0 {
			t.Fatalf("control %s is compliant with no evidence", c.ID)
		}
		if c.Status == StatusNonCompliant && c.Remediation == "" {
			t.Fatalf("control %s failed with no remediation guidance", c.ID)
		}
	}
}

func TestControlStatus_DependsOnRuntimeInput(t *testing.T) {
	cases := []struct {
		control    string
		input      VerificationInput
		wantStatus string
		wantSubstr string // substring of evidence or remediation text
	}{
		{"PCI-6.4", fullInput(t), StatusCompliant, "2 of 2 sites"},
		{"PCI-6.4", VerificationInput{TotalSites: 3, ProtectedSites: 0}, StatusNonCompliant, "0 of 3 configured sites"},
		{"PCI-6.4", VerificationInput{}, StatusNonCompliant, "no sites are configured"},
		{"PCI-6.5.1", fullInput(t), StatusCompliant, "inspector=sqli"},
		{"PCI-6.5.1", VerificationInput{}, StatusNonCompliant, "SQL injection inspector is not registered"},
		{"PCI-6.5.2", fullInput(t), StatusCompliant, "inspector=xss"},
		{"PCI-6.5.2", VerificationInput{}, StatusNonCompliant, "cross-site scripting inspector is not registered"},
		{"PCI-6.5.9", fullInput(t), StatusCompliant, "inspector=rce"},
		{"PCI-6.5.9", VerificationInput{}, StatusNonCompliant, "command injection inspector is not registered"},
		{"PCI-6.5.8", fullInput(t), StatusCompliant, "inspector=upload"},
		{"PCI-8.2", fullInput(t), StatusCompliant, "admin.api_keys configured"},
		{"PCI-8.2", VerificationInput{}, StatusNonCompliant, "admin API is open"},
		{"GDPR-Art32", fullInput(t), StatusCompliant, "min_version=1.2"},
		{"GDPR-Art32", VerificationInput{}, StatusNonCompliant, "TLS is disabled"},
		{"PCI-10.1", fullInput(t), StatusCompliant, "5 entries, chain integrity verified"},
		{"PCI-10.1", VerificationInput{}, StatusNonCompliant, "no audit log is attached"},
		{"PCI-10.1", VerificationInput{AuditLog: NewAuditLog()}, StatusNonCompliant, "contains no entries yet"},
		{"PCI-10.1", VerificationInput{AuditLog: tamperedLog(t)}, StatusNonCompliant, "verification FAILED"},
		{"PCI-10.1", VerificationInput{AuditLog: auditLogWith(t, 3)}, StatusCompliant, "3 entries"},
	}

	for _, tc := range cases {
		t.Run(tc.control, func(t *testing.T) {
			framework := FrameworkPCI
			if strings.HasPrefix(tc.control, "GDPR") {
				framework = FrameworkGDPR
			}
			ce := NewComplianceEngine(tc.input)
			ce.RunAssessment(framework)

			ctrl := ce.findControl(framework, tc.control)
			if ctrl == nil {
				t.Fatalf("control %s not defined", tc.control)
			}
			if ctrl.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", ctrl.Status, tc.wantStatus)
			}
			hay := ctrl.Remediation
			for _, ev := range ctrl.Evidence {
				hay += " " + ev.Description + " " + ev.Data
			}
			if !strings.Contains(hay, tc.wantSubstr) {
				t.Fatalf("%s: %q does not contain %q", tc.control, hay, tc.wantSubstr)
			}
		})
	}
}

// Controls that need human evidence must never be auto-marked compliant.
func TestUnverifiableControls_AreManual(t *testing.T) {
	ce := NewComplianceEngine(fullInput(t))
	ce.RunAssessment(FrameworkGDPR)

	for _, id := range []string{"GDPR-Art33", "GDPR-Art35", "GDPR-Art7-1"} {
		ctrl := ce.findControl(FrameworkGDPR, id)
		if ctrl == nil {
			t.Fatalf("control %s not defined", id)
		}
		if ctrl.Status != StatusManual {
			t.Fatalf("control %s: status = %q, want %q", id, ctrl.Status, StatusManual)
		}
		if ctrl.Remediation == "" {
			t.Fatalf("control %s: manual controls need remediation guidance", id)
		}
		if len(ctrl.Evidence) != 0 {
			t.Fatalf("control %s: manual controls must carry no evidence", id)
		}
	}
}

func TestGetComplianceStatus_CountsManualSeparately(t *testing.T) {
	ce := NewComplianceEngine(fullInput(t))
	ce.RunAssessment(FrameworkPCI)

	compliant, manual, total := ce.GetComplianceStatus(FrameworkPCI)
	if compliant == 0 || manual == 0 {
		t.Fatalf("expected both verified and manual controls, got compliant=%d manual=%d total=%d",
			compliant, manual, total)
	}
	if compliant+manual > total {
		t.Fatalf("compliant+manual (%d) exceeds total (%d)", compliant+manual, total)
	}
}

func TestExportCSV_HasAllRows(t *testing.T) {
	ce := NewComplianceEngine(fullInput(t))
	out, err := ce.ExportReport(FrameworkPCI, "csv")
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("csv export returned only %d lines (header only?)", len(lines))
	}
	for _, line := range lines {
		if len(strings.Split(line, ",")) != 4 {
			t.Fatalf("malformed csv line: %q", line)
		}
	}
}

func TestExportJSON(t *testing.T) {
	ce := NewComplianceEngine(fullInput(t))
	out, err := ce.ExportReport(FrameworkPCI, "json")
	if err != nil {
		t.Fatalf("export json: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("export json is not valid json: %v", err)
	}
}

func TestExportReport_UnsupportedFormat(t *testing.T) {
	ce := NewComplianceEngine(fullInput(t))
	if _, err := ce.ExportReport(FrameworkPCI, "xlsx"); err == nil {
		t.Fatal("expected an error for an unsupported export format")
	}
}

// --- Audit log -----------------------------------------------------------

func TestAuditLog_AppendAndVerifyChain(t *testing.T) {
	al := NewAuditLog()

	// A freshly created log used to be immutable by default, so every
	// Append failed - the audit trail could never record anything.
	for i := 0; i < 3; i++ {
		if err := al.Append(AuditEntry{
			ActorID: "admin", ActorType: "user", ActorIP: "127.0.0.1",
			Action: "login", Resource: "admin-api", Result: "success",
		}); err != nil {
			t.Fatalf("append entry %d: %v", i, err)
		}
	}
	if got := al.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}

	if valid, err := al.VerifyIntegrity(); err != nil || !valid {
		t.Fatalf("chain should verify: valid=%v err=%v", valid, err)
	}

	entries, err := al.Query(AuditFilter{ActorID: "admin"})
	if err != nil || len(entries) != 3 {
		t.Fatalf("query: %d entries, err=%v", len(entries), err)
	}
}

func TestAuditLog_EmptyTimeRangeMatchesEverything(t *testing.T) {
	al := NewAuditLog()
	for i := 0; i < 3; i++ {
		_ = al.Append(AuditEntry{ActorID: "admin", Action: "block"})
	}
	entries, err := al.Query(AuditFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("an empty filter must match all entries, got %d", len(entries))
	}
}

func TestAuditLog_DetectsTampering(t *testing.T) {
	al := tamperedLog(t)
	if valid, _ := al.VerifyIntegrity(); valid {
		t.Fatal("VerifyIntegrity must detect a modified entry")
	}
}

func TestAuditEntry_HashLinksEntries(t *testing.T) {
	al := auditLogWith(t, 2)

	entries, _ := al.Query(AuditFilter{})
	if entries[0].Hash != entries[1].PrevHash {
		t.Fatalf("entry 2 must chain to entry 1's hash")
	}
	if entries[0].PrevHash != "" {
		t.Fatalf("first entry must have an empty prev_hash")
	}
	if entries[0].Timestamp.IsZero() {
		t.Fatal("append must timestamp the entry")
	}
	if entries[0].ID == "" {
		t.Fatal("append must assign an entry ID")
	}
}

func (ce *ComplianceEngine) findControl(f ComplianceFramework, id string) *Control {
	for _, c := range ce.GetControls(f) {
		if c.ID == id {
			return &c
		}
	}
	return nil
}
