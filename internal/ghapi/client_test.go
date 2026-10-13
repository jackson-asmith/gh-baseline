package ghapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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
