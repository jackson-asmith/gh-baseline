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
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "gh-baseline: "+format+"\n", a...)
		return exitError
	}
	flags := flag.NewFlagSet("gh-baseline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		baselinePath = flags.String("baseline", "", "baseline file (JSON); default: every repo in the basic tier")
		owner        = flags.String("owner", "", "account to audit (overrides the baseline's owner)")
		hostname     = flags.String("hostname", "", "GitHub host (default: GH_HOST or github.com)")
		snapIn       = flags.String("snapshot", "", "evaluate a saved snapshot instead of calling the API")
		snapOut      = flags.String("save-snapshot", "", "write the collected snapshot to this file")
		format       = flags.String("format", "table", "output format: table, json, or sarif")
		all          = flags.Bool("all", false, "show passing and skipped checks too (table format)")
		repos        listFlag
	)
	flags.Var(&repos, "repo", "repository to audit (repeatable); default: all of the owner's repos")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: gh baseline [flags]\n\nReports where repositories drift from a declared security baseline.\n\nFlags:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if *format != "table" && *format != "json" && *format != "sarif" {
		return fail("unknown format %q", *format)
	}

	b := baseline.Default()
	if *baselinePath != "" {
		var err error
		if b, err = baseline.Load(*baselinePath); err != nil {
			return fail("%v", err)
		}
	}
	if *owner != "" {
		b.Owner = *owner
	}

	var snap *snapshot.Snapshot
	if *snapIn != "" {
		var err error
		if snap, err = snapshot.Load(*snapIn); err != nil {
			return fail("%v", err)
		}
	} else {
		if b.Owner == "" {
			return fail(`no owner: pass --owner or set "owner" in the baseline`)
		}
		api, err := ghapi.New(*hostname)
		if err != nil {
			return fail("%v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		c := &collect.Collector{API: api}
		snap, err = c.Collect(ctx, collect.Options{
			Owner:        b.Owner,
			Repos:        repos,
			IncludeForks: b.IncludeForks,
			Exclude:      b.Exclude,
		})
		if err != nil {
			return fail("%v", err)
		}
	}
	if *snapOut != "" {
		if err := snap.Save(*snapOut); err != nil {
			return fail("%v", err)
		}
	}

	findings := check.Evaluate(snap, b, time.Now())
	var err error
	switch *format {
	case "json":
		err = report.JSON(stdout, findings)
	case "sarif":
		err = report.SARIF(stdout, findings)
	default:
		err = report.Table(stdout, findings, *all)
	}
	if err != nil {
		return fail("%v", err)
	}
	if report.Summarize(findings).Fail > 0 {
		return exitFindings
	}
	return exitOK
}
