package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/report"
)

// webhookPayload is the JSON body POSTed to --webhook URLs.
// The shape is compatible with Slack's incoming webhook format when only
// the "text" field is populated, and also carries a machine-readable
// "nazar" block for custom integrations.
type webhookPayload struct {
	// Text is the Slack-compatible summary line.
	Text string `json:"text"`
	// Nazar contains structured data for non-Slack consumers.
	Nazar webhookNazar `json:"nazar"`
}

type webhookNazar struct {
	Tool      string         `json:"tool"`
	Version   string         `json:"version"`
	Timestamp string         `json:"timestamp"`
	Root      string         `json:"root"`
	Summary   webhookSummary `json:"summary"`
	Status    string         `json:"status"` // "clean" or "vulnerable"
}

type webhookSummary struct {
	Projects int `json:"projects"`
	Packages int `json:"packages"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total_vulns"`
	Fixable  int `json:"fixable"`
}

// sendWebhook posts the scan summary to url. Errors are logged to stderr but
// never returned — a failing webhook must not abort a scan that already completed.
func sendWebhook(url string, root string, results []report.Result) error {
	var sc webhookSummary
	sc.Projects = len(results)
	for _, r := range results {
		for _, pv := range r.Packages {
			sc.Packages++
			for _, v := range pv.Vulns {
				switch v.Severity {
				case osv.SeverityCritical:
					sc.Critical++
				case osv.SeverityHigh:
					sc.High++
				case osv.SeverityMedium:
					sc.Medium++
				case osv.SeverityLow:
					sc.Low++
				default:
					sc.Unknown++
				}
				sc.Total++
			}
			// Count package as fixable if any vuln has a fix.
			for _, v := range pv.Vulns {
				if v.FixedIn != "" {
					sc.Fixable++
					break
				}
			}
		}
	}

	status := "clean"
	if sc.Total > 0 {
		status = "vulnerable"
	}

	var text string
	if sc.Total == 0 {
		text = fmt.Sprintf("✓ nazar: 0 vulnerabilities found across %d project(s) in %s", sc.Projects, root)
	} else {
		text = fmt.Sprintf("⚠ nazar: %d vulnerabilities found (%d critical, %d high) across %d project(s) in %s",
			sc.Total, sc.Critical, sc.High, sc.Projects, root)
	}

	payload := webhookPayload{
		Text: text,
		Nazar: webhookNazar{
			Tool:      "nazar",
			Version:   version,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Root:      root,
			Summary:   sc,
			Status:    status,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST webhook: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
