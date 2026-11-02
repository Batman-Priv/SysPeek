package modules

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type reportPayload struct {
	GeneratedAt time.Time `json:"generated_at"`
	ThreatScore int       `json:"threat_score"`
	RiskLabel   string    `json:"risk_label"`
	Findings    []Finding `json:"findings"`
}

func ExportReport(format, path string) (string, error) {
	all := AllFindings()
	sort.Slice(all, func(i, j int) bool { return all[i].Severity > all[j].Severity })
	score := OverallRiskScore(all)

	switch strings.ToLower(format) {
	case "json":
		return exportJSON(path, score, all)
	case "csv":
		return exportCSV(path, all)
	case "html":
		return exportHTML(path, score, all)
	default:
		return "", fmt.Errorf("unsupported format %q (use json, csv, or html)", format)
	}
}

func exportJSON(path string, score int, all []Finding) (string, error) {
	if path == "" {
		path = "syspeek_report.json"
	}
	payload := reportPayload{GeneratedAt: time.Now(), ThreatScore: score, RiskLabel: riskLabel(score), Findings: all}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}

func exportCSV(path string, all []Finding) (string, error) {
	if path == "" {
		path = "syspeek_report.csv"
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"Timestamp", "Module", "Severity", "Subject", "Title", "MITRE"}); err != nil {
		return "", err
	}
	for _, fnd := range all {
		row := []string{
			fnd.Timestamp.Format(time.RFC3339),
			fnd.Module,
			strconv.Itoa(fnd.Severity),
			fnd.Subject,
			fnd.Title,
			strings.Join(fnd.Mitre, ";"),
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}
	return path, nil
}

func exportHTML(path string, score int, all []Finding) (string, error) {
	if path == "" {
		path = "syspeek_report.html"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>SysPeek Report</title>
<style>
body{font-family:Consolas,Menlo,monospace;background:#0d1117;color:#c9d1d9;padding:2rem}
h1{color:#58a6ff;margin-bottom:0} table{border-collapse:collapse;width:100%%;margin-top:1.2rem}
th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:13px}
th{background:#161b22} tr:nth-child(even){background:#12161c}
.score{font-size:2.2rem;font-weight:bold;margin-top:.3rem}
.crit{color:#f85149} .high{color:#db6d28} .med{color:#d29922} .low{color:#3fb950}
.meta{color:#8b949e;font-size:13px}
</style></head><body>
<h1>SysPeek Threat Report</h1>
<div class="score">Threat Score: %d/100 &nbsp;[%s]</div>
<div class="meta">Generated: %s &middot; %d findings</div>
<table><tr><th>Time</th><th>Severity</th><th>Module</th><th>Subject</th><th>Finding</th><th>MITRE ATT&amp;CK</th></tr>`,
		score, riskLabel(score), time.Now().Format(time.RFC1123), len(all)))

	for _, fnd := range all {
		cls := "low"
		switch {
		case fnd.Severity >= 80:
			cls = "crit"
		case fnd.Severity >= 50:
			cls = "high"
		case fnd.Severity >= 20:
			cls = "med"
		}

		var mitreParts []string
		for _, m := range fnd.Mitre {
			mitreParts = append(mitreParts, m+" "+MitreName(m))
		}

		b.WriteString(fmt.Sprintf(`<tr class="%s"><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			cls,
			fnd.Timestamp.Format("15:04:05"),
			fnd.Severity,
			html.EscapeString(fnd.Module),
			html.EscapeString(fnd.Subject),
			html.EscapeString(fnd.Title),
			html.EscapeString(strings.Join(mitreParts, ", ")),
		))
	}
	b.WriteString(`</table></body></html>`)

	return path, os.WriteFile(path, []byte(b.String()), 0o644)
}
