package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The admin API must reject an oversized body with 413 rather than buffering
// it unbounded. This guards the memory-exhaustion path on every JSON handler.
func TestDecodeJSONBody_RejectsOversized(t *testing.T) {
	huge := `{"title":"` + strings.Repeat("A", maxAdminBodyBytes+1024) + `"}`

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(huge))
	rec := httptest.NewRecorder()

	var dst struct {
		Title string `json:"title"`
	}
	err := decodeJSONBody(rec, req, &dst)
	if err == nil {
		t.Fatal("expected an error for an oversized body")
	}

	// The caller answers with writeDecodeError; check it maps to 413.
	rec2 := httptest.NewRecorder()
	writeDecodeError(rec2, err)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec2.Code)
	}
}

func TestDecodeJSONBody_AcceptsSmall(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"title":"ok"}`))
	rec := httptest.NewRecorder()
	var dst struct {
		Title string `json:"title"`
	}
	if err := decodeJSONBody(rec, req, &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.Title != "ok" {
		t.Fatalf("decoded %q, want ok", dst.Title)
	}
}

// Unknown fields are rejected, so a typo in a config payload fails loudly.
func TestDecodeJSONBody_RejectsUnknownField(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"nope":1}`))
	rec := httptest.NewRecorder()
	var dst struct {
		Title string `json:"title"`
	}
	if err := decodeJSONBody(rec, req, &dst); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}
