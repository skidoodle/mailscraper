package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
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
				<span data-cfemail="53303513362b323e233f367d303c3e"></span>
				<p>Obfuscated: user [at] example [dot] com</p>
				<p>ROT13: rot13unique@example.com -> ebg13havdhr@rknzcyr.pbz</p>
				<p>ROT13: ebg13havdhr@rknzcyr.pbz</p>
				<p>Unicode: \u006d\u0061\u0069\u006c\u0040\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002e\u0063\u006f\u006d</p>
				<script>var x = Math.min(1, 2);</script>
				<style>.at { color: red; }</style>
			</body>
		</html>
	`

	seen.Lock()
	seen.m = make(map[string]struct{})
	seen.Unlock()

	emails := scan(strings.NewReader(html), true)

	expected := []string{
		"test1@example.com",
		"test2@example.com",
		"support@company.org",
		"test3@example.com",
		"cf@example.com",
		"user@example.com",
		"rot13unique@example.com",
		"mail@example.com",
	}

	if len(emails) < len(expected) {
		t.Errorf("expected at least %d emails, got %d: %v", len(expected), len(emails), emails)
	}

	// Test parse error coverage
	badReader := &errorReader{}
	scan(badReader, true)
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
	res := &targetResult{}
	emails, err := fetch(context.Background(), ts.URL, ts.URL, cfg, res)
	if err != nil {
		t.Errorf("fetch failed: %v", err)
	}
	if len(emails) == 0 {
		t.Error("expected emails to be found")
	}

	// Test server error
	_, err = fetch(context.Background(), ts.URL+"/error", ts.URL+"/error", cfg, res)
	if err == nil {
		t.Error("expected error from 500 status")
	}

	// Test request creation error (invalid URL)
	_, err = fetch(context.Background(), "%%", "%%", cfg, res)
	if err == nil {
		t.Error("expected error from invalid URL")
	}

	// Test network error (closed server)
	ts.Close()
	_, err = fetch(context.Background(), ts.URL, ts.URL, cfg, res)
	if err == nil {
		t.Error("expected network error")
	}
}

func TestIsNew(t *testing.T) {
	seen.Lock()
	seen.m = make(map[string]struct{})
	seen.Unlock()

	if isNew("") != false {
		t.Error("isNew empty string should return false")
	}
	if isNew("not-an-email") != false {
		t.Error("isNew invalid email should return false")
	}
	if isNew("A@B.COM") != true {
		t.Error("first record should return true")
	}
	if isNew("a@b.com") != false {
		t.Error("duplicate record should return false")
	}
}

func TestParseHex(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
		ok       bool
	}{
		{"0", 0, true},
		{"f", 15, true},
		{"F", 15, true},
		{"10", 16, true},
		{"ffff", 65535, true},
		{"", 0, false},
		{"g", 0, false},
	}

	for _, tt := range tests {
		got, ok := parseHex(tt.input)
		if got != tt.expected || ok != tt.ok {
			t.Errorf("parseHex(%q) = (%d, %v); want (%d, %v)", tt.input, got, ok, tt.expected, tt.ok)
		}
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
	}

	for _, tt := range tests {
		got := unescapeUnicode(tt.input)
		if got != tt.expected {
			t.Errorf("unescapeUnicode(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}

	// Test the !ok branch by temporarily changing the regex
	oldRE := unicodeRE
	unicodeRE = regexp.MustCompile(`\\u[0-9a-gA-G]{4}`)
	defer func() { unicodeRE = oldRE }()

	if unescapeUnicode("\\u003G") != "\\u003G" {
		t.Error("expected unchanged string for invalid hex")
	}
}

func TestDecodeCloudflare(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"53303513362b323e233f367d303c3e", "cf@example.com"},
		{"", ""},
		{"5", ""},
		{"gg", ""},
		{"533g", ""},
	}

	for _, tt := range tests {
		got := decodeCloudflare(tt.input)
		if got != tt.expected {
			t.Errorf("decodeCloudflare(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDeobfuscate(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user [at] example [dot] com", "user@example.com"},
		{"user (at) example (dot) com", "user@example.com"},
		{"user  at  example  dot  com", "user@example.com"},
		{"Math.min", "Math.min"},
		{"no change", "no change"},
	}

	for _, tt := range tests {
		got := deobfuscate(tt.input)
		if got != tt.expected {
			t.Errorf("deobfuscate(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMainLogic(t *testing.T) {
	// Setup a mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "test@example.com")
	}))
	defer ts.Close()

	// Create a temp file for -f test
	tmpFile := filepath.Join(t.TempDir(), "urls.txt")
	os.WriteFile(tmpFile, []byte(ts.URL+"\n  \n"+ts.URL), 0644)

	// Save original args/stderr/exit/stdin
	oldArgs := os.Args
	oldStderr := os.Stderr
	oldStdin := os.Stdin
	defer func() {
		os.Args = oldArgs
		os.Stderr = oldStderr
		os.Stdin = oldStdin
	}()

	// Capture log output to discard it
	log.SetOutput(io.Discard)

	tests := []struct {
		name  string
		args  []string
		stdin string
	}{
		{"NoArgs", []string{"cmd"}, ""},
		{"WithURL", []string{"cmd", "-v", ts.URL, " ", "example.com"}, ""},
		{"WithFile", []string{"cmd", "-v", "-f", tmpFile}, ""},
		{"WithStdinDash", []string{"cmd", "-"}, ts.URL},
		{"WithStdinAuto", []string{"cmd"}, ts.URL},
		{"WithFetchError", []string{"cmd", "http://invalid.local.nonexistent"}, ""},
		{"WithInsecure", []string{"cmd", "-k", ts.URL}, ""},
		{"WithVerboseFailure", []string{"cmd", "-v", "http://invalid.local.nonexistent"}, ""},
		{"WithQuiet", []string{"cmd", "-q", ts.URL}, ""},
		{"WithVersion", []string{"cmd", "-version"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset seen
			seen.Lock()
			seen.m = make(map[string]struct{})
			seen.Unlock()

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

			// Setup stdin if needed
			if tt.stdin != "" {
				r, w, _ := os.Pipe()
				os.Stdin = r
				go func() {
					fmt.Fprintln(w, tt.stdin)
					w.Close()
				}()
			} else {
				r, w, _ := os.Pipe()
				os.Stdin = r
				w.Close()
			}

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

func TestMainFileError(t *testing.T) {
	oldExit := osExit
	defer func() { osExit = oldExit }()

	exitCalled := false
	osExit = func(code int) {
		exitCalled = true
		panic("exit")
	}

	os.Args = []string{"cmd", "-f", "non-existent-file"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	log.SetOutput(io.Discard)

	defer func() {
		recover()
		if !exitCalled {
			t.Error("expected exit on file error")
		}
	}()

	main()
}
