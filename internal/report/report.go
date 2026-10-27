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

// SARIF writes findings as a SARIF 2.1.0 document for upload to GitHub code
// scanning. Only fail and unknown findings produce results; pass and skip are
// omitted. All rules in the catalog are listed in the driver regardless of
// whether they fired, so code scanning can track suppressed findings.
// Locations are repo-level logical locations (no physical file path).
func SARIF(w io.Writer, fs []check.Finding) error {
	catalog := check.Catalog()
	rules := make([]sarifRule, len(catalog))
	for i, d := range catalog {
		rules[i] = sarifRule{
			ID:               d.ID,
			ShortDescription: sarifText{Text: d.ID},
			Help:             sarifText{Text: d.Remediation},
			Properties:       sarifRuleProps{SecuritySeverity: sarifSecuritySeverity(d.Severity)},
		}
	}

	results := []sarifResult{}
	for _, f := range fs {
		if f.Status != check.Fail && f.Status != check.Unknown {
			continue
		}
		results = append(results, sarifResult{
			RuleID:  f.Check,
			Level:   sarifLevel(f.Status, f.Severity),
			Message: sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{Name: f.Repo, Kind: "repository"}},
			}},
		})
	}

	doc := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "gh-baseline",
				InformationURI: "https://github.com/jackson-asmith/gh-baseline",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifLevel maps a finding's status and severity to a SARIF level.
// unknown findings use "warning" regardless of severity: the data wasn't
// readable, so the finding is not a confirmed failure but should stay visible.
func sarifLevel(status check.Status, severity check.Severity) string {
	if status == check.Unknown {
		return "warning"
	}
	switch severity {
	case check.High:
		return "error"
	case check.Low:
		return "note"
	default:
		return "warning"
	}
}

func sarifSecuritySeverity(s check.Severity) string {
	switch s {
	case check.High:
		return "8.0"
	case check.Low:
		return "2.0"
	default:
		return "5.0"
	}
}

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	Help             sarifText      `json:"help"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	SecuritySeverity string `json:"security-severity"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}
