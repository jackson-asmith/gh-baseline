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
		t.Errorf("github.com: %s", got)
	}
	if got := APIBase("ghe.example.com"); got != "https://ghe.example.com/api/v3" {
		t.Errorf("enterprise: %s", got)
	}
}

func TestNextLink(t *testing.T) {
	h := `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`
	if got := nextLink(h); got != "https://api.github.com/x?page=2" {
		t.Errorf("got %q", got)
	}
	if got := nextLink(`<https://api.github.com/x?page=1>; rel="prev"`); got != "" {
		t.Errorf("got %q, want none", got)
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
		t.Fatalf("want not found, got %v", err)
	}
	if err.Error() != "HTTP 404: Not Found" {
		t.Errorf("message: %q", err.Error())
	}
}
