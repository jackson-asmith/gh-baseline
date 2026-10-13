// Package report renders findings.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/jackson-asmith/gh-baseline/internal/check"
)

// Summary counts findings by status.
type Summary struct {
	Pass, Fail, Unknown, Skip int
}

// Summarize counts findings by status.
func Summarize(fs []check.Finding) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Status {
		case check.Pass:
			s.Pass++
		case check.Fail:
			s.Fail++
		case check.Unknown:
			s.Unknown++
		case check.Skip:
			s.Skip++
		}
	}
	return s
}

// Table writes findings as an aligned table. Unless all is set, only failures
// and unknowns are shown, followed by their remediations.
func Table(w io.Writer, fs []check.Finding, all bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "REPO\tCHECK\tSTATUS\tSEVERITY\tDETAIL")
	for _, f := range fs {
		if !all && f.Status != check.Fail && f.Status != check.Unknown {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Repo, f.Check, f.Status, f.Severity, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fixes := map[string]string{}
	var order []string
	for _, f := range fs {
		if f.Remediation != "" {
			if _, ok := fixes[f.Check]; !ok {
				order = append(order, f.Check)
			}
			fixes[f.Check] = f.Remediation
		}
	}
	if len(order) > 0 {
		fmt.Fprintln(w, "\nHow to fix:")
		for _, id := range order {
			fmt.Fprintf(w, "  %s: %s\n", id, fixes[id])
		}
	}

	s := Summarize(fs)
	_, err := fmt.Fprintf(w, "\n%d failed, %d unknown, %d passed, %d skipped\n", s.Fail, s.Unknown, s.Pass, s.Skip)
	return err
}

// JSON writes all findings as an indented JSON array.
func JSON(w io.Writer, fs []check.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if fs == nil {
		fs = []check.Finding{}
	}
	return enc.Encode(fs)
}
