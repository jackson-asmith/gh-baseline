// Command gh-baseline reports where an account's repositories drift from a
// declared security baseline. Install it as a gh extension:
//
//	gh extension install jackson-asmith/gh-baseline
//	gh baseline --baseline baseline.json
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackson-asmith/gh-baseline/internal/baseline"
	"github.com/jackson-asmith/gh-baseline/internal/check"
	"github.com/jackson-asmith/gh-baseline/internal/collect"
	"github.com/jackson-asmith/gh-baseline/internal/ghapi"
	"github.com/jackson-asmith/gh-baseline/internal/report"
	"github.com/jackson-asmith/gh-baseline/internal/snapshot"
)

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1 // at least one check failed
	exitError    = 2 // bad usage or the run itself failed
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gh-baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		baselinePath = fs.String("baseline", "", "baseline file (JSON); default: every repo in the basic tier")
		owner        = fs.String("owner", "", "account to audit (overrides the baseline's owner)")
		hostname     = fs.String("hostname", "", "GitHub host (default: GH_HOST or github.com)")
		snapIn       = fs.String("snapshot", "", "evaluate a saved snapshot instead of calling the API")
		snapOut      = fs.String("save-snapshot", "", "write the collected snapshot to this file")
		format       = fs.String("format", "table", "output format: table or json")
		all          = fs.Bool("all", false, "show passing and skipped checks too (table format)")
		repos        listFlag
	)
	fs.Var(&repos, "repo", "repository to audit (repeatable); default: all of the owner's repos")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: gh baseline [flags]\n\nReports where repositories drift from a declared security baseline.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintf(stderr, "unknown format %q\n", *format)
		return exitError
	}

	b := baseline.Default()
	if *baselinePath != "" {
		var err error
		if b, err = baseline.Load(*baselinePath); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
	}
	if *owner != "" {
		b.Owner = *owner
	}

	var snap *snapshot.Snapshot
	if *snapIn != "" {
		var err error
		if snap, err = snapshot.Load(*snapIn); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
	} else {
		if b.Owner == "" {
			fmt.Fprintln(stderr, "no owner: pass --owner or set \"owner\" in the baseline")
			return exitError
		}
		api, err := ghapi.New(*hostname)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		c := &collect.Collector{API: api, Host: api.Host}
		snap, err = c.Collect(ctx, collect.Options{
			Owner:        b.Owner,
			Repos:        repos,
			IncludeForks: b.IncludeForks,
			Exclude:      b.Exclude,
		})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
	}
	if *snapOut != "" {
		if err := snap.Save(*snapOut); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
	}

	findings := check.Evaluate(snap, b, time.Now())
	var err error
	if *format == "json" {
		err = report.JSON(stdout, findings)
	} else {
		err = report.Table(stdout, findings, *all)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if report.Summarize(findings).Fail > 0 {
		return exitFindings
	}
	return exitOK
}
