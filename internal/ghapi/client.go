// Package ghapi is a minimal, read-only GitHub REST client built on net/http.
package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Client issues GET requests against the GitHub REST API.
type Client struct {
	Host    string
	BaseURL string
	Token   string
	HTTP    *http.Client
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

// Get fetches path (relative to BaseURL, or an absolute URL) into v.
// It returns the response's next-page URL, if any.
func (c *Client) Get(ctx context.Context, path string, v any) (next string, err error) {
	target := path
	if !strings.HasPrefix(path, "https://") {
		target = c.BaseURL + "/" + strings.TrimPrefix(path, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &msg)
		return "", &StatusError{Status: resp.StatusCode, Message: msg.Message}
	}
	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			return "", fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return nextLink(resp.Header.Get("Link")), nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func nextLink(h string) string {
	if m := linkNext.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}
