package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type DesyncDetector struct {
	mu            sync.RWMutex
	devMode       bool
	maxBodySize   int64
	strictCL      bool
	detectOBSFold bool
	clTeRE        *regexp.Regexp
	obsFoldRE     *regexp.Regexp
	chunkedRE     *regexp.Regexp
}

func NewDesyncDetector(devMode bool, maxBodySize int64, strictCL, detectOBSFold bool) *DesyncDetector {
	return &DesyncDetector{
		devMode:       devMode,
		maxBodySize:   maxBodySize,
		strictCL:      strictCL,
		detectOBSFold: detectOBSFold,
		clTeRE:        regexp.MustCompile(`(?i)^\s*Content-Length\s*:\s*\d+\s*$`),
		obsFoldRE:     regexp.MustCompile(`(?m)^\s+(?:[a-zA-Z-]+):`),
		chunkedRE:     regexp.MustCompile(`(?i)Transfer-Encoding\s*:\s*chunked`),
	}
}

func (d *DesyncDetector) Name() string { return "desync" }

func (d *DesyncDetector) Inspect(ctx *RequestContext) (*Decision, error) {
	if ctx.Request == nil {
		return nil, nil
	}

	dec := d.checkCLTE(ctx)
	if dec != nil {
		return dec, nil
	}

	dec = d.checkTECL(ctx)
	if dec != nil {
		return dec, nil
	}

	dec = d.checkOBSFold(ctx)
	if dec != nil {
		return dec, nil
	}

	dec = d.checkContentLengthAnomaly(ctx)
	if dec != nil {
		return dec, nil
	}

	dec = d.checkDuplicateHeaders(ctx)
	if dec != nil {
		return dec, nil
	}

	dec = d.checkTEHeader(ctx)
	if dec != nil {
		return dec, nil
	}

	return nil, nil
}

func (d *DesyncDetector) checkCLTE(ctx *RequestContext) *Decision {
	cl := ctx.Request.Header.Get("Content-Length")
	te := ctx.Request.Header.Get("Transfer-Encoding")

	if cl != "" && strings.Contains(strings.ToLower(te), "chunked") {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "DSYNC_001",
			RuleName: "CL.TE Desync",
			Severity: "critical",
			Score:    95,
			Evidence: fmt.Sprintf("Content-Length and Transfer-Encoding: chunked both present (CL.TE smuggling)"),
		}
	}

	// Check for multiple Content-Length headers (CL.CL variant)
	cls := ctx.Request.Header.Values("Content-Length")
	if len(cls) > 1 {
		vals := make([]string, 0)
		for _, v := range cls {
			trimmed := strings.TrimSpace(v)
			if trimmed != "" {
				vals = append(vals, trimmed)
			}
		}
		if len(vals) > 1 {
			first := vals[0]
			for _, v := range vals[1:] {
				if v != first {
					return &Decision{
						Action:   ActionBlock,
						RuleID:   "DSYNC_002",
						RuleName: "Multiple Content-Length (CL.CL)",
						Severity: "critical",
						Score:    90,
						Evidence: fmt.Sprintf("mismatched Content-Length headers: %s", strings.Join(vals, ", ")),
					}
				}
			}
		}
	}

	return nil
}

func (d *DesyncDetector) checkTECL(ctx *RequestContext) *Decision {
	te := ctx.Request.Header.Get("Transfer-Encoding")
	cl := ctx.Request.Header.Get("Content-Length")

	if strings.Contains(strings.ToLower(te), "chunked") && cl != "" {
		// TE.CL - Transfer-Encoding says chunked but Content-Length also present
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "DSYNC_003",
			RuleName: "TE.CL Desync",
			Severity: "critical",
			Score:    95,
			Evidence: fmt.Sprintf("Transfer-Encoding: chunked with Content-Length present (TE.CL smuggling)"),
		}
	}

	return nil
}

func (d *DesyncDetector) checkOBSFold(ctx *RequestContext) *Decision {
	if !d.detectOBSFold {
		return nil
	}

	rawHeaders := ctx.Headers
	for k, v := range rawHeaders {
		if strings.HasPrefix(k, " ") || strings.HasPrefix(v, " ") {
			// Obs-fold: header starts with whitespace (folded)
			if d.strictCL {
				return &Decision{
					Action:   ActionBlock,
					RuleID:   "DSYNC_004",
					RuleName: "Obs-fold Header",
					Severity: "high",
					Score:    75,
					Evidence: fmt.Sprintf("obs-fold header detected: %q", k),
				}
			}
			return &Decision{
				Action:   ActionMonitor,
				RuleID:   "DSYNC_004",
				RuleName: "Obs-fold Header",
				Severity: "medium",
				Score:    40,
				Evidence: fmt.Sprintf("obs-fold header detected: %q", k),
			}
		}
	}

	return nil
}

func (d *DesyncDetector) checkContentLengthAnomaly(ctx *RequestContext) *Decision {
	cls := ctx.Request.Header.Values("Content-Length")
	if len(cls) == 0 {
		return nil
	}

	cl := strings.TrimSpace(cls[0])
	if cl == "" {
		return nil
	}

	val, err := strconv.ParseInt(cl, 10, 64)
	if err != nil {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "DSYNC_005",
			RuleName: "Invalid Content-Length",
			Severity: "high",
			Score:    70,
			Evidence: fmt.Sprintf("non-numeric Content-Length: %q", cl),
		}
	}

	if val < 0 {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "DSYNC_006",
			RuleName: "Negative Content-Length",
			Severity: "high",
			Score:    80,
			Evidence: fmt.Sprintf("negative Content-Length: %d", val),
		}
	}

	if d.maxBodySize > 0 && val > d.maxBodySize {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "DSYNC_007",
			RuleName: "Content-Length Exceeds Limit",
			Severity: "medium",
			Score:    30,
			Evidence: fmt.Sprintf("Content-Length %d exceeds max %d", val, d.maxBodySize),
		}
	}

	return nil
}

func (d *DesyncDetector) checkDuplicateHeaders(ctx *RequestContext) *Decision {
	seen := make(map[string]int)
	for k := range ctx.Headers {
		lower := strings.ToLower(k)
		seen[lower]++
	}

	for k, count := range seen {
		if count > 1 {
			if k == "content-length" || k == "transfer-encoding" || k == "host" {
				continue // already handled by other checks
			}
			if d.strictCL {
				return &Decision{
					Action:   ActionMonitor,
					RuleID:   "DSYNC_008",
					RuleName: "Duplicate Header",
					Severity: "medium",
					Score:    20,
					Evidence: fmt.Sprintf("header %q appears %d times (potential smuggling)", k, count),
				}
			}
		}
	}

	return nil
}

func (d *DesyncDetector) checkTEHeader(ctx *RequestContext) *Decision {
	te := ctx.Request.Header.Get("TE")
	if te != "" {
		teLower := strings.ToLower(te)
		if strings.Contains(teLower, "chunked") || strings.Contains(teLower, "trailers") {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "DSYNC_009",
				RuleName: "TE Header Present",
				Severity: "high",
				Score:    70,
				Evidence: fmt.Sprintf("TE header with sensitive value: %q", te),
			}
		}
	}

	return nil
}
