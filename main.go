package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

var (
	// Version info set via ldflags by goreleaser
	Version    = "(devel)"
	Commit     = "none"
	CommitDate = "unknown"

	// emailRE matches common email address formats.
	emailRE = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)

	// seen tracks unique emails across all targets.
	seen = struct {
		sync.Mutex
		m map[string]struct{}
	}{m: make(map[string]struct{})}

	// out is where emails are written.
	out io.Writer = os.Stdout

	// osExit is the exit function (mockable for tests).
	osExit = os.Exit

	// unicodeRE matches \uXXXX sequences.
	unicodeRE = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)

	// common obfuscation patterns. Only match if bracketed or as independent words.
	atPatterns  = regexp.MustCompile(`(?i)(\s+[\[\(\{\s]*at[\]\)\}\s]*\s+|[\[\(\{\s]+at[\]\)\}\s]+)`)
	dotPatterns = regexp.MustCompile(`(?i)(\s+[\[\(\{\s]*dot[\]\)\}\s]*\s+|[\[\(\{\s]+dot[\]\)\}\s]+)`)
)

// rot13 decodes a rot13 encoded string.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, s)
}

type config struct {
	timeout  time.Duration
	verbose  bool
	quiet    bool
	insecure bool
	ua       string
	file     string
}

type targetResult struct {
	orig   string
	emails []string
	err    error
	status string
}

func main() {
	log.SetFlags(0)

	var cfg config
	var showVersion bool
	flag.DurationVar(&cfg.timeout, "t", 15*time.Second, "network timeout")
	flag.BoolVar(&cfg.verbose, "v", false, "verbose output")
	flag.BoolVar(&cfg.quiet, "q", false, "suppress non-error output")
	flag.BoolVar(&cfg.insecure, "k", false, "allow insecure SSL connections")
	flag.StringVar(&cfg.ua, "a", "mailscraper/1.1", "user-agent string")
	flag.StringVar(&cfg.file, "f", "", "read URLs from file")
	flag.BoolVar(&showVersion, "version", false, "show version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-v] [-q] [-k] [-t timeout] [-a useragent] [-f file] [url ... | -]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if showVersion {
		v, c, d := getVersion(Version, Commit, CommitDate, debug.ReadBuildInfo)
		fmt.Printf("mailscraper %s (%s) built at %s\n", v, c, d)
		return
	}

	targets := flag.Args()

	// Handle file input
	if cfg.file != "" {
		f, err := os.Open(cfg.file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open file: %v\n", err)
			osExit(1)
			return
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if t := strings.TrimSpace(scanner.Text()); t != "" {
				targets = append(targets, t)
			}
		}
		f.Close()
	}

	// Handle stdin if no targets or "-" is present
	useStdin := false
	for i, t := range targets {
		if t == "-" {
			useStdin = true
			targets = append(targets[:i], targets[i+1:]...)
			break
		}
	}
	if len(targets) == 0 || useStdin {
		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if t := strings.TrimSpace(scanner.Text()); t != "" {
					targets = append(targets, t)
				}
			}
		}
	}

	if len(targets) == 0 {
		flag.Usage()
		osExit(1)
		return
	}

	if cfg.verbose {
		fmt.Fprintf(os.Stderr, "processing %d targets\n", len(targets))
	}

	if cfg.insecure {
		if tr, ok := http.DefaultTransport.(*http.Transport); ok {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}

	var wg sync.WaitGroup
	ctx := context.Background()
	var exitCode int
	var exitMu sync.Mutex
	results := make([]targetResult, len(targets))

	for i, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		original := target
		if !strings.HasPrefix(target, "http") {
			target = "https://" + target
		}

		wg.Add(1)
		go func(idx int, u, orig string) {
			defer wg.Done()
			res := targetResult{orig: orig}
			emails, err := fetch(ctx, u, orig, cfg, &res)
			if err != nil {
				res.err = err
				exitMu.Lock()
				exitCode = 1
				exitMu.Unlock()
			}
			res.emails = emails
			results[idx] = res
		}(i, target, original)
	}

	wg.Wait()

	var failedTargets []string
	for _, res := range results {
		if res.err != nil {
			msg := "[network error]"
			if cfg.verbose {
				msg = fmt.Sprintf("network error: %v", res.err)
			}
			fmt.Fprintf(os.Stderr, "%s: %s\n", res.orig, msg)
			failedTargets = append(failedTargets, res.orig)
			continue
		}
		for _, email := range res.emails {
			fmt.Fprintf(out, "%s: %s\n", res.orig, email)
		}
		if res.status != "" && !cfg.quiet {
			fmt.Fprintf(os.Stderr, "%s: %s\n", res.orig, res.status)
		}
	}

	if cfg.verbose && !cfg.quiet {
		seen.Lock()
		count := len(seen.m)
		fmt.Fprintf(os.Stderr, "done: found %d unique emails across %d targets\n", count, len(targets))
		if len(failedTargets) > 0 {
			fmt.Fprintf(os.Stderr, "failed targets: %s\n", strings.Join(failedTargets, ", "))
		}
		seen.Unlock()
	}

	if exitCode != 0 {
		osExit(exitCode)
	}
}

// getVersion resolves the version, commit, and date using build info if needed.
func getVersion(v, c, d string, rbi func() (*debug.BuildInfo, bool)) (string, string, string) {
	if info, ok := rbi(); ok {
		if v == "dev" || v == "" || v == "(devel)" {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				v = info.Main.Version
			}
		}

		if (c == "none" || c == "") && strings.Contains(v, "-") {
			parts := strings.Split(v, "-")
			if len(parts) >= 3 {
				c = parts[len(parts)-1]
				if (d == "unknown" || d == "") && len(parts[len(parts)-2]) == 14 {
					t, err := time.Parse("20060102150405", parts[len(parts)-2])
					if err == nil {
						d = t.Format(time.RFC3339)
					}
				}
			}
		}

		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "none" || c == "" {
					c = s.Value
				}
			case "vcs.time":
				if d == "unknown" || d == "" {
					d = s.Value
				}
			}
		}
	}
	return v, c, d
}

// fetch retrieves the target URL and triggers parsing.
func fetch(ctx context.Context, u, orig string, cfg config, res *targetResult) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	req.Header.Set("User-Agent", cfg.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	emails := scan(resp.Body, cfg.verbose)
	if len(emails) == 0 {
		res.status = "[no emails found]"
	} else if cfg.verbose {
		res.status = fmt.Sprintf("extracted %d emails", len(emails))
	}
	return emails, nil
}

// scan tokenizes the HTML and extracts emails from links and text.
func scan(r io.Reader, verbose bool) []string {
	var emails []string
	var skip bool
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if err := z.Err(); err != io.EOF && verbose {
				fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
			}
			return emails
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == "script" || t.Data == "style" {
				skip = true
			}
			// Check for data-cfemail (Cloudflare)
			for _, a := range t.Attr {
				if a.Key == "data-cfemail" {
					if email := decodeCloudflare(a.Val); email != "" {
						if isNew(email) {
							emails = append(emails, email)
						}
					}
				}
				if t.Data == "a" && a.Key == "href" && strings.HasPrefix(strings.ToLower(a.Val), "mailto:") {
					val := a.Val[7:]
					if dec, err := url.PathUnescape(val); err == nil {
						email := strings.SplitN(dec, "?", 2)[0]
						email = strings.TrimSpace(email)
						if isNew(email) {
							emails = append(emails, email)
						}
					}
				}
			}
		case html.EndTagToken:
			t := z.Token()
			if t.Data == "script" || t.Data == "style" {
				skip = false
			}
		case html.TextToken:
			if skip {
				continue
			}
			t := z.Token()
			data := unescapeUnicode(t.Data)
			data = deobfuscate(data)
			for _, m := range emailRE.FindAllString(data, -1) {
				if isNew(m) {
					emails = append(emails, m)
				}
			}
			// Try ROT13 as well
			r13 := rot13(data)
			for _, m := range emailRE.FindAllString(r13, -1) {
				if isNew(m) {
					emails = append(emails, m)
				}
			}
		}
	}
}

// parseHex converts a hex string to uint32 without strconv.
func parseHex(s string) (uint32, bool) {
	var n uint32
	if len(s) == 0 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		var v byte
		switch {
		case s[i] >= '0' && s[i] <= '9':
			v = s[i] - '0'
		case s[i] >= 'a' && s[i] <= 'f':
			v = s[i] - 'a' + 10
		case s[i] >= 'A' && s[i] <= 'F':
			v = s[i] - 'A' + 10
		default:
			return 0, false
		}
		n = (n << 4) | uint32(v)
	}
	return n, true
}

// unescapeUnicode replaces \uXXXX sequences with their actual characters.
func unescapeUnicode(s string) string {
	return unicodeRE.ReplaceAllStringFunc(s, func(m string) string {
		r, ok := parseHex(m[2:])
		if !ok {
			return m
		}
		return string(rune(r))
	})
}

// decodeCloudflare decodes Cloudflare email protection.
func decodeCloudflare(hex string) string {
	if len(hex) < 2 {
		return ""
	}
	k, ok := parseHex(hex[:2])
	if !ok {
		return ""
	}
	var b strings.Builder
	for i := 2; i < len(hex)-1; i += 2 {
		c, ok := parseHex(hex[i : i+2])
		if !ok {
			return ""
		}
		b.WriteByte(byte(c ^ k))
	}
	return b.String()
}

// deobfuscate handles patterns like "user [at] example [dot] com".
func deobfuscate(s string) string {
	s = atPatterns.ReplaceAllString(s, "@")
	s = dotPatterns.ReplaceAllString(s, ".")
	return s
}

// isNew checks if an email is unique and records it.
func isNew(email string) bool {
	if email == "" {
		return false
	}
	email = strings.ToLower(email)
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return false
	}
	seen.Lock()
	defer seen.Unlock()
	if _, ok := seen.m[email]; !ok {
		seen.m[email] = struct{}{}
		return true
	}
	return false
}
