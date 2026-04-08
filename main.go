package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

var (
	// emailRE matches common email address formats.
	emailRE = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

	// seen tracks unique emails across all targets.
	seen = struct {
		sync.Mutex
		m map[string]struct{}
	}{m: make(map[string]struct{})}

	// out is where emails are written.
	out io.Writer = os.Stdout

	// osExit is the exit function (mockable for tests).
	osExit = os.Exit
)

type config struct {
	timeout time.Duration
	verbose bool
	ua      string
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("mailscraper: ")

	var cfg config
	flag.DurationVar(&cfg.timeout, "t", 15*time.Second, "network timeout")
	flag.BoolVar(&cfg.verbose, "v", false, "verbose output")
	flag.StringVar(&cfg.ua, "a", "mailscraper/1.1", "user-agent string")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-v] [-t timeout] [-a useragent] url ...\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		osExit(1)
		return
	}

	if cfg.verbose {
		log.Printf("processing %d targets", len(targets))
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	for _, target := range targets {
		if !strings.HasPrefix(target, "http") {
			target = "https://" + target
		}

		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			if err := fetch(ctx, u, cfg); err != nil {
				log.Printf("%s: %v", u, err)
			}
		}(target)
	}

	wg.Wait()

	if cfg.verbose {
		seen.Lock()
		log.Printf("done: found %d unique emails across %d targets", len(seen.m), len(targets))
		seen.Unlock()
	}
}

// fetch retrieves the target URL and triggers parsing.
func fetch(ctx context.Context, u string, cfg config) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	if cfg.verbose {
		log.Printf("%s: initializing request", u)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", cfg.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if cfg.verbose {
		log.Printf("%s: %d %s (took %v)", u, resp.StatusCode, http.StatusText(resp.StatusCode), time.Since(start).Round(time.Millisecond))
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	found := scan(resp.Body, u, cfg.verbose)
	if cfg.verbose {
		log.Printf("%s: extracted %d emails", u, found)
	}
	return nil
}

// scan tokenizes the HTML and extracts emails from links and text.
func scan(r io.Reader, u string, verbose bool) int {
	var count int
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if err := z.Err(); err != io.EOF && verbose {
				log.Printf("%s: parse error: %v", u, err)
			}
			return count
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == "a" {
				for _, a := range t.Attr {
					if a.Key == "href" && strings.HasPrefix(strings.ToLower(a.Val), "mailto:") {
						val := a.Val[7:]
						if dec, err := url.PathUnescape(val); err == nil {
							email := strings.SplitN(dec, "?", 2)[0]
							if record(strings.TrimSpace(email)) {
								count++
							}
						}
					}
				}
			}
		case html.TextToken:
			t := z.Token()
			for _, m := range emailRE.FindAllString(t.Data, -1) {
				if record(m) {
					count++
				}
			}
		}
	}
}

// record saves unique emails and prints them to stdout.
func record(email string) bool {
	if email == "" {
		return false
	}
	email = strings.ToLower(email)
	seen.Lock()
	defer seen.Unlock()
	if _, ok := seen.m[email]; !ok {
		seen.m[email] = struct{}{}
		fmt.Fprintln(out, email)
		return true
	}
	return false
}
