// Package ghapi is a minimal, read-only GitHub REST client built on net/http.
package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Retry policy, matching keel.Http's Invoke-WithBoundedRetry.
const (
	maxAttempts   = 3                      // including the first
	baseDelay     = 500 * time.Millisecond // doubles on each retry
	maxBackoff    = 5 * time.Second
	maxJitter     = 250 * time.Millisecond
	maxRetryAfter = 60 * time.Second // longer requested waits fail instead
)

// retryableStatus are the transient responses worth retrying. Every request
// is a GET, so retrying an ambiguous 500, 502, or 504 can't repeat a change.
var retryableStatus = map[int]bool{
	http.StatusRequestTimeout:      true,
	http.StatusTooManyRequests:     true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
}

// Client issues GET requests against the GitHub REST API.
type Client struct {
	Host    string
	BaseURL string
	Token   string
	HTTP    *http.Client

	// sleep waits between retries; tests replace it. Nil means sleepCtx.
	sleep func(context.Context, time.Duration) error
}

// StatusError is returned for non-2xx responses.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
}

// RateLimitError is returned when the hourly API budget is exhausted and
// won't reset soon enough to wait for.
type RateLimitError struct {
	Reset time.Time
}

func (e *RateLimitError) Error() string {
	return "GitHub API rate limit exhausted; resets at " + e.Reset.Local().Format(time.Kitchen)
}

// IsRateLimited reports whether err is an exhausted rate limit.
func IsRateLimited(err error) bool {
	var rle *RateLimitError
	return errors.As(err, &rle)
}

// IsNotFound reports whether err is a 404 from the API.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}

// New builds a client for host (empty means GH_HOST or github.com), taking the
// token from GH_TOKEN, GITHUB_TOKEN, or `gh auth token`.
func New(host string) (*Client, error) {
	if host == "" {
		host = os.Getenv("GH_HOST")
	}
	if host == "" {
		host = "github.com"
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		out, err := exec.Command("gh", "auth", "token", "--hostname", host).Output()
		if err == nil {
			token = strings.TrimSpace(string(out))
		}
	}
	if token == "" {
		return nil, errors.New("no token: set GH_TOKEN or run `gh auth login`")
	}
	return &Client{
		Host:    host,
		BaseURL: APIBase(host),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// APIBase returns the REST API root for a host.
func APIBase(host string) string {
	if host == "github.com" {
		return "https://api.github.com"
	}
	return "https://" + host + "/api/v3"
}

// Get fetches path (relative to BaseURL, or an absolute URL under it) into v.
// It returns the response's next-page URL, if any. Absolute URLs elsewhere are
// refused so the token is never sent to another host.
//
// Transient failures are retried with exponential backoff (see retryDelay).
// An exhausted rate limit returns a *RateLimitError.
func (c *Client) Get(ctx context.Context, path string, v any) (next string, err error) {
	target := c.BaseURL + "/" + strings.TrimPrefix(path, "/")
	if strings.Contains(path, "://") {
		if !strings.HasPrefix(path, c.BaseURL+"/") {
			return "", fmt.Errorf("refusing to send credentials to %s: not under %s", path, c.BaseURL)
		}
		target = path
	}
	sleep := c.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	for attempt := 1; ; attempt++ {
		body, header, err := c.get(ctx, target)
		if err == nil {
			if v != nil {
				if err := json.Unmarshal(body, v); err != nil {
					return "", fmt.Errorf("decode %s: %w", path, err)
				}
			}
			return nextLink(header.Get("Link")), nil
		}
		var se *StatusError
		if !errors.As(err, &se) {
			return "", err // network errors aren't retried
		}
		delay, ok, err := retryDelay(se, header, attempt)
		if !ok || attempt == maxAttempts {
			return "", err
		}
		if err := sleep(ctx, delay); err != nil {
			return "", err
		}
	}
}

// get issues one request. Non-2xx responses return a *StatusError along with
// the response headers, which carry the retry hints.
func (c *Client) get(ctx context.Context, target string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &msg)
		return nil, resp.Header, &StatusError{Status: resp.StatusCode, Message: msg.Message}
	}
	return body, resp.Header, nil
}

// retryDelay decides whether a failed attempt is worth retrying and how long
// to wait first. It returns the error to report when it isn't.
//
// The policy is keel.Http's: retry the statuses in retryableStatus, honoring
// Retry-After up to maxRetryAfter and otherwise backing off exponentially with
// jitter. GitHub also signals rate limits with a 403, so a 403 is retried when
// it carries Retry-After (a secondary limit), and an exhausted hourly budget
// (X-RateLimit-Remaining: 0) waits for the reset if it's close and otherwise
// returns a *RateLimitError.
func retryDelay(se *StatusError, h http.Header, attempt int) (time.Duration, bool, error) {
	jitter := rand.N(maxJitter)
	limited := se.Status == http.StatusForbidden || se.Status == http.StatusTooManyRequests
	if limited && h.Get("X-RateLimit-Remaining") == "0" {
		reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64)
		if err != nil {
			return 0, false, se
		}
		wait := time.Until(time.Unix(reset, 0))
		if wait > maxRetryAfter {
			return 0, false, &RateLimitError{Reset: time.Unix(reset, 0)}
		}
		return max(wait, 0) + jitter, true, se
	}
	retryAfter, hasRetryAfter := parseRetryAfter(h.Get("Retry-After"))
	if !retryableStatus[se.Status] && !(se.Status == http.StatusForbidden && hasRetryAfter) {
		return 0, false, se
	}
	if hasRetryAfter {
		if retryAfter > maxRetryAfter {
			return 0, false, se
		}
		return retryAfter + jitter, true, se
	}
	return min(baseDelay<<(attempt-1)+jitter, maxBackoff), true, se
}

// parseRetryAfter reads a Retry-After header in either of its forms: a number
// of seconds or an HTTP date.
func parseRetryAfter(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0), true
	}
	return 0, false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(h string) string {
	if m := linkNext.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}
