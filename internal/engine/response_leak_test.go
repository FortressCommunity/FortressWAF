package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// awsKeyFixture is an AWS-key-SHAPED test value. It is assembled so no
// AWS-shaped literal sits in the source (secret scanners match the format).
var awsKeyFixture = "AKIA" + strings.Repeat("0", 16)

// TestResponseLeakDetectsSecrets asserts that every rule fires on a realistic
// leaked value. These are the payloads the demo sends to an origin whose
// response accidentally echoes a credential.
func TestResponseLeakDetectsSecrets(t *testing.T) {
	insp := NewResponseLeakInspector(true, true, 1<<20)

	// A JWT fixture is assembled from parts rather than written as one literal.
	// A complete, well-formed JWT in source trips secret scanners even when the
	// value is synthetic; building it here keeps the detector test intact while
	// leaving no JWT-shaped string in the file.
	jwtFixture := strings.Join([]string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"eyJzdWIiOiJmaXh0dXJlIiwibmFtZSI6InRlc3QifQ",
		"c2lnbmF0dXJlLW5vdC1hLXJlYWwta2V5LXBsYWNlaG9sZGVy",
	}, ".")

	cases := []struct {
		name     string
		ct       string
		body     string
		wantRule string
	}{
		{
			name:     "rsa private key",
			ct:       "text/plain",
			body:     "here is the key\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----",
			wantRule: "LEAK-001",
		},
		{
			name:     "openssh private key",
			ct:       "application/x-pem-file",
			body:     "-----BEGIN OPENSSH PRIVATE KEY-----",
			wantRule: "LEAK-001",
		},
		{
			name:     "aws access key id",
			ct:       "application/json",
			body:     `{"AccessKeyId":"` + awsKeyFixture + `"}`,
			wantRule: "LEAK-002",
		},
		{
			name:     "json web token",
			ct:       "application/json",
			body:     `{"token":"` + jwtFixture + `"}`,
			wantRule: "LEAK-003",
		},
		{
			name:     "openai style api key",
			ct:       "application/json",
			body:     `{"key":"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}`,
			wantRule: "LEAK-004",
		},
		{
			name: "github personal access token",
			ct:   "text/plain",
			// Assembled so no token-shaped literal sits in the file.
			body:     "ghp_" + strings.Repeat("a", 36),
			wantRule: "LEAK-004",
		},
		{
			name:     "postgres dsn with password",
			ct:       "application/json",
			body:     `{"dsn":"postgres://admin:s3cr3tP@ssw0rd@db.internal:5432/app"}`,
			wantRule: "LEAK-005",
		},
		{
			name:     "bcrypt hash",
			ct:       "application/json",
			body:     `{"password_hash":"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"}`,
			wantRule: "LEAK-006",
		},
		{
			name:     "go stack trace",
			ct:       "text/plain",
			body:     "panic: runtime error: invalid memory address\ngoroutine 1 [running]:\nmain.main()",
			wantRule: "LEAK-007",
		},
		{
			name:     "python traceback",
			ct:       "text/html",
			body:     "<pre>Traceback (most recent call last):\n  File \"app.py\", line 1</pre>",
			wantRule: "LEAK-007",
		},
		{
			name:     "cloud metadata credential",
			ct:       "application/json",
			body:     `{"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
			wantRule: "LEAK-008",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := insp.InspectResponse(tc.ct, http.StatusOK, []byte(tc.body))
			if dec == nil {
				t.Fatalf("expected rule %s to fire on %q, got no decision", tc.wantRule, tc.body)
			}
			if dec.RuleID != tc.wantRule {
				t.Fatalf("expected rule %s, got %s (%s)", tc.wantRule, dec.RuleID, dec.RuleName)
			}
			if dec.Action != ActionBlock || !dec.Blocked {
				t.Fatalf("leak decision must block, got action=%s blocked=%v", dec.Action, dec.Blocked)
			}
		})
	}
}

// TestResponseLeakNoFalsePositives is the credibility test: ordinary responses
// that merely *mention* security words must not be blocked.
func TestResponseLeakNoFalsePositives(t *testing.T) {
	insp := NewResponseLeakInspector(true, true, 1<<20)

	benign := []struct {
		name string
		ct   string
		body string
	}{
		{"prose with password word", "text/html",
			"<p>Forgot your password? Reset it here. Never share your password with anyone.</p>"},
		{"blog about javascript", "text/html",
			"<article>JavaScript is fun. This tutorial covers script tags, the DOM, and event handlers.</article>"},
		{"json without secrets", "application/json",
			`{"user":"alice","password_field_present":true,"select_option":"monthly"}`},
		{"dotted version string", "application/json",
			`{"version":"1.2.3","build":"eyJub3QifQ"}`},
		{"normal log line", "text/plain",
			"2024-01-01 INFO request completed status=200 path=/api/health"},
		{"html with api word", "text/html",
			"<a href=\"/api/v1/docs\">API documentation</a>"},
		{"empty body", "application/json", ""},
		{"binary image", "image/png", "-----BEGIN RSA PRIVATE KEY-----"},
	}

	for _, tc := range benign {
		t.Run(tc.name, func(t *testing.T) {
			if dec := insp.InspectResponse(tc.ct, http.StatusOK, []byte(tc.body)); dec != nil {
				t.Fatalf("false positive: %q matched %s (%s)", tc.body, dec.RuleID, dec.RuleName)
			}
		})
	}
}

// TestResponseLeakEvidenceIsRedacted asserts the WAF's own logs never store the
// leaked value in full.
func TestResponseLeakEvidenceIsRedacted(t *testing.T) {
	insp := NewResponseLeakInspector(true, true, 1<<20)
	secret := awsKeyFixture
	dec := insp.InspectResponse("application/json", http.StatusOK,
		[]byte(`{"AccessKeyId":"`+secret+`"}`))
	if dec == nil {
		t.Fatal("expected AWS key to be detected")
	}
	if strings.Contains(dec.Evidence, secret) {
		t.Fatalf("evidence leaked the raw secret: %s", dec.Evidence)
	}
}

// TestResponseLeakDisabled asserts inspection can be turned off entirely.
func TestResponseLeakDisabled(t *testing.T) {
	insp := NewResponseLeakInspector(false, false, 1<<20)
	dec := insp.InspectResponse("application/json", http.StatusOK,
		[]byte(`{"AccessKeyId":"`+awsKeyFixture+`"}`))
	if dec != nil {
		t.Fatal("disabled inspector must not flag anything")
	}
}

// TestResponseLeakMonitorByDefault asserts the default mode reports a leak
// without blocking, so a content match cannot take a legitimate page down.
func TestResponseLeakMonitorByDefault(t *testing.T) {
	insp := NewResponseLeakInspector(true, false, 1<<20)
	dec := insp.InspectResponse("application/json", http.StatusOK,
		[]byte(`{"AccessKeyId":"`+awsKeyFixture+`"}`))
	if dec == nil {
		t.Fatal("expected the leak to be reported")
	}
	if dec.Action != ActionMonitor || dec.Blocked {
		t.Fatalf("default mode must monitor, got action=%s blocked=%v", dec.Action, dec.Blocked)
	}
}

// TestResponseLeakRespectsScanWindow asserts a body larger than the scan window
// is capped, not buffered whole.
func TestResponseLeakRespectsScanWindow(t *testing.T) {
	insp := NewResponseLeakInspector(true, true, 64)
	// Secret sits past the 64-byte window; must not be detected.
	body := strings.Repeat("x", 200) + awsKeyFixture
	if dec := insp.InspectResponse("text/plain", http.StatusOK, []byte(body)); dec != nil {
		t.Fatalf("secret beyond scan window should be ignored, got %s", dec.RuleID)
	}
}

// TestResponseWriterBuffersUntilCommit asserts the writer holds the origin body
// so a leak decision can still be made before the client sees it.
func TestResponseWriterBuffersUntilCommit(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := NewResponseWriter(rec, true, 1<<20)

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if _, err := rw.Write([]byte(`{"secret":"` + awsKeyFixture + `"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Nothing must have reached the client yet.
	if rec.Body.Len() != 0 {
		t.Fatalf("body reached client before commit: %q", rec.Body.String())
	}

	if dec := NewResponseLeakInspector(true, true, 1<<20).InspectResponse(
		rw.Header().Get("Content-Type"), rw.StatusCode, rw.Body); dec == nil {
		t.Fatal("expected leak to be detected in buffered body")
	}

	// Discarding keeps the origin body from leaking through.
	rw.Discard()
	if rec.Body.Len() != 0 {
		t.Fatalf("discarded body still reached client: %q", rec.Body.String())
	}
}

// TestResponseWriterCommitPassesThrough asserts a clean response is delivered
// unchanged.
func TestResponseWriterCommitPassesThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := NewResponseWriter(rec, true, 1<<20)

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	body := `{"status":"ok","items":[1,2,3]}`
	if _, err := rw.Write([]byte(body)); err != nil {
		t.Fatalf("write: %v", err)
	}
	rw.Commit()

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != body {
		t.Fatalf("body altered on commit: got %q want %q", rec.Body.String(), body)
	}
}

// TestResponseWriterOversizedStreamsThrough asserts a body larger than the
// buffer is delivered whole and in order, without holding it all in memory.
func TestResponseWriterOversizedStreamsThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	const cap = 16
	rw := NewResponseWriter(rec, true, cap)

	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.WriteHeader(http.StatusOK)
	// Write in small chunks so the overflow path is exercised across calls.
	full := ""
	for i := 0; i < 10; i++ {
		chunk := "0123456789"
		full += chunk
		if _, err := rw.Write([]byte(chunk)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	rw.Commit()

	if rec.Body.String() != full {
		t.Fatalf("oversized body corrupted: got %q want %q", rec.Body.String(), full)
	}
}

// TestResponseWriterDiscardDropsOriginHeaders asserts the block path does not
// leave the origin's Content-Length (or entity headers) on the reply, which
// would make the client's framing mismatch.
func TestResponseWriterDiscardDropsOriginHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := NewResponseWriter(rec, true, 1<<20)

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Length", "66")
	rw.Header().Set("Set-Cookie", "session=abc")
	rw.WriteHeader(http.StatusOK)
	if _, err := rw.Write([]byte(`{"secret":"` + awsKeyFixture + `"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}

	if dec := NewResponseLeakInspector(true, true, 1<<20).InspectResponse(
		rw.Header().Get("Content-Type"), rw.StatusCode, rw.Body); dec == nil {
		t.Fatal("expected leak detection")
	}

	out := rw.Discard()
	for _, h := range []string{"Content-Length", "Content-Type", "Set-Cookie"} {
		if v := out.Header().Get(h); v != "" {
			t.Fatalf("origin header %s survived discard: %q", h, v)
		}
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("origin body reached client after discard: %q", rec.Body.String())
	}
}
