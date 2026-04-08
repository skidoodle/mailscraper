package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	html := `
		<html>
			<body>
				<a href="mailto:test1@example.com">Contact Us</a>
				<p>Email us at test2@example.com or support@company.org</p>
				<a href="mailto:TEST1@EXAMPLE.COM?subject=hello">Repeat</a>
				<div>Encoded: <a href="mailto:test3%40example.com">Encoded</a></div>
				<a href="/relative">Relative</a>
				<a href="https://example.com">External</a>
			</body>
		</html>
	`

	seen.Lock()
	seen.m = make(map[string]struct{})
	seen.Unlock()

	var buf bytes.Buffer
	oldOut := out
	out = &buf
	defer func() { out = oldOut }()

	found := scan(strings.NewReader(html), "http://example.com", true)

	if found != 4 {
		t.Errorf("expected 4 emails found, got %d", found)
	}

	expected := []string{"support@company.org", "test1@example.com", "test2@example.com", "test3@example.com"}
	output := strings.TrimSpace(buf.String())
	results := strings.Split(output, "\n")
	sort.Strings(results)
	sort.Strings(expected)

	for i := range results {
		if results[i] != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], results[i])
		}
	}

	// Test empty/invalid inputs for scan
	if scan(strings.NewReader(""), "http://empty.com", false) != 0 {
		t.Error("expected 0 from empty reader")
	}

	// Test parse error coverage
	// html.NewTokenizer doesn't easily error on strings, but we can mock a broken reader
	badReader := &errorReader{}
	scan(badReader, "http://bad.com", true)
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("read error")
}

func TestFetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "contact: dev@example.com")
	}))
	defer ts.Close()

	cfg := config{
		timeout: 2 * time.Second,
		verbose: true,
		ua:      "test-agent",
	}

	seen.Lock()
	seen.m = make(map[string]struct{})
	seen.Unlock()

	// Test successful fetch
	err := fetch(context.Background(), ts.URL, cfg)
	if err != nil {
		t.Errorf("fetch failed: %v", err)
	}

	// Test server error
	err = fetch(context.Background(), ts.URL+"/error", cfg)
	if err == nil {
		t.Error("expected error from 500 status")
	}

	// Test request creation error (invalid URL)
	err = fetch(context.Background(), "%%", cfg)
	if err == nil {
		t.Error("expected error from invalid URL")
	}

	// Test network error (closed server)
	ts.Close()
	err = fetch(context.Background(), ts.URL, cfg)
	if err == nil {
		t.Error("expected network error")
	}
}

func TestRecord(t *testing.T) {
	seen.Lock()
	seen.m = make(map[string]struct{})
	seen.Unlock()

	if record("") != false {
		t.Error("record empty string should return false")
	}
	if record("A@B.COM") != true {
		t.Error("first record should return true")
	}
	if record("a@b.com") != false {
		t.Error("duplicate record should return false")
	}
}

func TestUnescapeUnicode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"no unicode", "no unicode"},
		{"\\u003c", "<"},
		{"hello \\u003cworld\\u003e", "hello <world>"},
		{"\\u", "\\u"},
		{"\\uGHIJ", "\\uGHIJ"},
		{"\\u123456789", "\\u123456789"},
	}

	for _, tt := range tests {
		got := unescapeUnicode(tt.input)
		if got != tt.expected {
			t.Errorf("unescapeUnicode(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMainLogic(t *testing.T) {
	// Setup a mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "test@example.com")
	}))
	defer ts.Close()

	// Save original args/stderr/exit
	oldArgs := os.Args
	oldStderr := os.Stderr
	defer func() {
		os.Args = oldArgs
		os.Stderr = oldStderr
	}()

	// Capture log output to discard it
	log.SetOutput(io.Discard)

	tests := []struct {
		name string
		args []string
	}{
		{"NoArgs", []string{"cmd"}},
		{"WithURL", []string{"cmd", "-v", ts.URL}},
		{"WithMultipleURLs", []string{"cmd", "-v", ts.URL, ts.URL}},
		{"InvalidURL", []string{"cmd", "http://invalid.local"}},
		{"NoProtocol", []string{"cmd", "example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save current exit func and restore after
			oldExit := osExit
			defer func() { osExit = oldExit }()

			exitCalled := false
			osExit = func(code int) {
				exitCalled = true
				panic("exit")
			}

			os.Args = tt.args
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

			defer func() {
				r := recover()
				if tt.name == "NoArgs" && (r == nil || !exitCalled) {
					t.Errorf("expected exit(1) for NoArgs")
				}
			}()

			main()
		})
	}
}
