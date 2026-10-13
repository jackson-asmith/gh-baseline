package ghapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestAPIBase(t *testing.T) {
	if got := APIBase("github.com"); got != "https://api.github.com" {
		t.Errorf("APIBase(%q) = %q, want %q", "github.com", got, "https://api.github.com")
	}
	if got := APIBase("ghe.example.com"); got != "https://ghe.example.com/api/v3" {
		t.Errorf("APIBase(%q) = %q, want %q", "ghe.example.com", got, "https://ghe.example.com/api/v3")
	}
}

func TestNextLink(t *testing.T) {
	h := `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`
	if got := nextLink(h); got != "https://api.github.com/x?page=2" {
		t.Errorf("nextLink(next+last) = %q, want page=2", got)
	}
	if got := nextLink(`<https://api.github.com/x?page=1>; rel="prev"`); got != "" {
		t.Errorf("nextLink(prev only) = %q, want \"\"", got)
	}
}

func TestGetErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	_, err := c.Get(context.Background(), "repos/a/b", nil)
	if !IsNotFound(err) {
		t.Fatalf("Get(404) error = %v, want a not-found StatusError", err)
	}
	if err.Error() != "HTTP 404: Not Found" {
		t.Errorf("Get(404) error = %q, want %q", err.Error(), "HTTP 404: Not Found")
	}
}

func TestGetRefusesOtherHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			t.Errorf("unexpected request to %s", r.URL)
		}
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	for _, u := range []string{"https://evil.example.com/x", srv.URL + ".evil.example.com/x"} {
		if _, err := c.Get(context.Background(), u, nil); err == nil {
			t.Errorf("Get(%q) = nil error, want refusal", u)
		}
	}
	if _, err := c.Get(context.Background(), srv.URL+"/ok", nil); err != nil {
		t.Errorf("Get(%q) = %v, want success for a URL under BaseURL", srv.URL+"/ok", err)
	}
}

// response is one canned reply from fakeServer.
type response struct {
	status  int
	headers map[string]string
}

// fakeServer replies with responses in order, then 200 {} for any further
// request, and counts requests.
func fakeServer(t *testing.T, responses ...response) (*httptest.Server, *int) {
	t.Helper()
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n > len(responses) {
			fmt.Fprint(w, `{}`)
			return
		}
		resp := responses[n-1]
		for k, v := range resp.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(resp.status)
		fmt.Fprint(w, `{"message":"canned"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// recordingClient returns a client whose retry waits are recorded, not slept.
func recordingClient(srv *httptest.Server) (*Client, *[]time.Duration) {
	var waits []time.Duration
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client(),
		sleep: func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		}}
	return c, &waits
}

func TestGetRetries(t *testing.T) {
	inAnHour := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	inTenSeconds := strconv.FormatInt(time.Now().Add(10*time.Second).Unix(), 10)

	tests := []struct {
		name      string
		responses []response
		wantErr   bool
		wantCalls int
		// Each retry wait must fall in [min, min+spread).
		wantWaits []time.Duration
		spread    time.Duration
	}{
		{
			name:      "transient then success backs off exponentially",
			responses: []response{{status: 503}, {status: 502}},
			wantCalls: 3,
			wantWaits: []time.Duration{500 * time.Millisecond, time.Second},
			spread:    maxJitter,
		},
		{
			name:      "every retryable status",
			responses: []response{{status: 408}, {status: 500}},
			wantCalls: 3,
			wantWaits: []time.Duration{500 * time.Millisecond, time.Second},
			spread:    maxJitter,
		},
		{
			name:      "gives up after max attempts",
			responses: []response{{status: 504}, {status: 504}, {status: 504}},
			wantErr:   true,
			wantCalls: maxAttempts,
			wantWaits: []time.Duration{500 * time.Millisecond, time.Second},
			spread:    maxJitter,
		},
		{
			name:      "not found is not retried",
			responses: []response{{status: 404}},
			wantErr:   true,
			wantCalls: 1,
		},
		{
			name:      "plain 403 is not retried",
			responses: []response{{status: 403}},
			wantErr:   true,
			wantCalls: 1,
		},
		{
			name:      "403 with Retry-After is a secondary rate limit",
			responses: []response{{status: 403, headers: map[string]string{"Retry-After": "2"}}},
			wantCalls: 2,
			wantWaits: []time.Duration{2 * time.Second},
			spread:    maxJitter,
		},
		{
			name:      "Retry-After as an HTTP date",
			responses: []response{{status: 429, headers: map[string]string{"Retry-After": time.Now().Add(20 * time.Second).UTC().Format(http.TimeFormat)}}},
			wantCalls: 2,
			wantWaits: []time.Duration{18 * time.Second},
			spread:    3 * time.Second, // the date has one-second resolution
		},
		{
			name:      "Retry-After beyond the cap fails immediately",
			responses: []response{{status: 429, headers: map[string]string{"Retry-After": "120"}}},
			wantErr:   true,
			wantCalls: 1,
		},
		{
			name:      "exhausted budget resetting soon waits for the reset",
			responses: []response{{status: 403, headers: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": inTenSeconds}}},
			wantCalls: 2,
			wantWaits: []time.Duration{8 * time.Second},
			spread:    3 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, calls := fakeServer(t, tt.responses...)
			c, waits := recordingClient(srv)
			_, err := c.Get(context.Background(), "x", nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Get() error = %v, wantErr %v", err, tt.wantErr)
			}
			if *calls != tt.wantCalls {
				t.Errorf("Get() made %d requests, want %d", *calls, tt.wantCalls)
			}
			if len(*waits) != len(tt.wantWaits) {
				t.Fatalf("Get() waited %v, want %d waits", *waits, len(tt.wantWaits))
			}
			for i, got := range *waits {
				if lo := tt.wantWaits[i]; got < lo || got >= lo+tt.spread {
					t.Errorf("wait %d = %v, want in [%v, %v)", i, got, lo, lo+tt.spread)
				}
			}
		})
	}

	t.Run("exhausted budget resetting later stops with a RateLimitError", func(t *testing.T) {
		srv, calls := fakeServer(t, response{status: 403, headers: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": inAnHour}})
		c, waits := recordingClient(srv)
		_, err := c.Get(context.Background(), "x", nil)
		if !IsRateLimited(err) {
			t.Fatalf("Get() error = %v, want a RateLimitError", err)
		}
		if *calls != 1 || len(*waits) != 0 {
			t.Errorf("Get() made %d requests and waited %v, want 1 request and no waits", *calls, *waits)
		}
	})
}

func TestGetStopsWaitingWhenContextEnds(t *testing.T) {
	srv, calls := fakeServer(t, response{status: 503})
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()} // real sleep
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, "x", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Get() error = %v, want context.DeadlineExceeded", err)
	}
	if *calls != 1 {
		t.Errorf("Get() made %d requests, want 1", *calls)
	}
}
