package traincorpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorKeepsHighConfidenceAttack(t *testing.T) {
	dir := t.TempDir()
	c := NewCollector(dir)

	kept, reason := c.Consider(Sample{
		RuleID:     "SQLI016",
		Payload:    "1' OR '1'='1",
		ActorIP:    "1.2.3.4",
		Score:      90,
		ObservedAt: time.Now(),
	})
	if !kept {
		t.Fatalf("expected payload to be collected, reason=%q", reason)
	}

	payloads, err := LoadCategory(dir, "sql-injection")
	if err != nil {
		t.Fatalf("LoadCategory: %v", err)
	}
	if len(payloads) != 1 || payloads[0] != "1' OR '1'='1" {
		t.Fatalf("corpus = %v, want the payload", payloads)
	}
}

func TestCollectorDropsUntrustedRule(t *testing.T) {
	c := NewCollector(t.TempDir())
	// An accumulated-score challenge rule is not a named attack family.
	kept, _ := c.Consider(Sample{RuleID: "PROT010", Payload: "OPTIONS /", Score: 99, ObservedAt: time.Now()})
	if kept {
		t.Fatal("a non-attack rule must not be collected")
	}
}

func TestCollectorDropsLowScore(t *testing.T) {
	c := NewCollector(t.TempDir())
	kept, reason := c.Consider(Sample{RuleID: "SQLI016", Payload: "1' OR 1=1", Score: 40, ObservedAt: time.Now()})
	if kept {
		t.Fatalf("low-score sample must be dropped (reason=%q)", reason)
	}
}

func TestCollectorDropsProse(t *testing.T) {
	c := NewCollector(t.TempDir())
	// A benign sentence that happened to trip a rule is not a payload.
	kept, _ := c.Consider(Sample{RuleID: "SQLI016", Payload: "please select the blue option", Score: 90, ObservedAt: time.Now()})
	if kept {
		t.Fatal("prose must not be collected as an attack")
	}
}

func TestCollectorDeduplicates(t *testing.T) {
	c := NewCollector(t.TempDir())
	s := Sample{RuleID: "XSS001", Payload: "<script>alert(1)</script>", Score: 90, ObservedAt: time.Now()}
	if kept, _ := c.Consider(s); !kept {
		t.Fatal("first occurrence should be kept")
	}
	if kept, _ := c.Consider(s); kept {
		t.Fatal("duplicate should be dropped")
	}
	_, _, unique := c.Stats()
	if unique != 1 {
		t.Fatalf("unique = %d, want 1", unique)
	}
}

func TestCollectorSanitizesMultilinePayload(t *testing.T) {
	dir := t.TempDir()
	c := NewCollector(dir)
	kept, _ := c.Consider(Sample{
		RuleID:     "SQLI016",
		Payload:    "1' OR 1=1\nDROP TABLE users\t\x00",
		Score:      95,
		ObservedAt: time.Now(),
	})
	if !kept {
		t.Fatal("payload should be collected after sanitizing")
	}
	payloads, _ := LoadCategory(dir, "sql-injection")
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %v", payloads)
	}
	if strings.ContainsAny(payloads[0], "\n\t\x00") {
		t.Fatalf("payload still contains control characters: %q", payloads[0])
	}
}

func TestLoadCategorySkipsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xss", "payloads.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "# a comment\n<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\t# from 1.2.3.4\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	payloads, err := LoadCategory(dir, "xss")
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("got %d payloads, want 2: %v", len(payloads), payloads)
	}
	if payloads[1] != "<img src=x onerror=alert(1)>" {
		t.Fatalf("annotation not stripped: %q", payloads[1])
	}
}
