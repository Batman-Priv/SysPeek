package modules

import (
	"fmt"
	"sort"
	"strings"
)

func OverallRiskScore(all []Finding) int {
	if len(all) == 0 {
		return 0
	}
	sevs := make([]int, len(all))
	for i, f := range all {
		sevs[i] = f.Severity
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sevs)))

	score := 0.0
	weight := 1.0
	for _, s := range sevs {
		score += float64(s) * weight
		weight *= 0.4 
		if weight < 0.05 {
			break
		}
	}
	if score > 100 {
		score = 100
	}
	return int(score)
}

func riskLabel(score int) string {
	th := LoadConfig().Thresholds
	switch {
	case score >= th.High:
		return "CRITICAL"
	case score >= th.Medium:
		return "HIGH"
	case score >= th.Low:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "CLEAN"
	}
}

func recommendationsFor(techniqueSet map[string]bool) []string {
	var recs []string
	add := func(cond bool, text string) {
		if cond {
			recs = append(recs, text)
		}
	}
	add(techniqueSet["T1055"] || techniqueSet["T1055.001"],
		"Isolate the affected host and capture a memory image before further changes - process-injection findings degrade quickly once the process exits.")
	add(techniqueSet["T1574.001"],
		"Compare the flagged DLL against a known-good copy from the same Windows build; remove/quarantine if it doesn't match.")
	add(techniqueSet["T1036.001"] || techniqueSet["T1553.002"],
		"Treat any TAMPERED-signature finding as high-confidence compromise - the file was modified after being signed.")
	add(techniqueSet["T1059.001"] || techniqueSet["T1218.011"] || techniqueSet["T1218.010"] || techniqueSet["T1218.005"],
		"Pull PowerShell ScriptBlock/Module logs (Event ID 4104) and Sysmon Event ID 1 for the full command line and parent chain.")
	add(techniqueSet["T1543.003"] || techniqueSet["T1053.005"] || techniqueSet["T1547.001"] || techniqueSet["T1547.006"],
		"New persistence since baseline - verify with the software owner before removing; check install timestamp against known change windows.")
	if len(recs) == 0 {
		recs = append(recs, "No high-confidence indicators this run. Consider a deeper pass with --processes=0 for a full inventory.")
	}
	return recs
}

func RenderCorrelationReport() {
	all := AllFindings()
	score := OverallRiskScore(all)

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("  Threat Score: %d/100  [%s]\n", score, riskLabel(score))
	fmt.Println(strings.Repeat("=", 70))

	if len(all) == 0 {
		fmt.Println("\nNo findings registered this run. Run with --processes=1, --lolbin, or --diff to populate the correlation engine.")
		return
	}

	sorted := make([]Finding, len(all))
	copy(sorted, all)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Severity > sorted[j].Severity })

	fmt.Println("\nCritical & High Findings")
	fmt.Println(strings.Repeat("-", 40))
	shown := 0
	for _, f := range sorted {
		if f.Severity < 50 {
			break
		}
		mark := "\u2713" 
		fmt.Printf("%s [%3d] %-14s %-30s %s\n", mark, f.Severity, f.Module, f.Subject, f.Title)
		shown++
		if shown >= 15 {
			fmt.Println("  ... additional findings truncated, see full module output above")
			break
		}
	}
	if shown == 0 {
		fmt.Println("(none - all findings below HIGH threshold)")
	}

	techniqueSet := map[string]bool{}
	for _, f := range all {
		for _, t := range f.Mitre {
			techniqueSet[t] = true
		}
	}
	var techniques []string
	for t := range techniqueSet {
		techniques = append(techniques, t)
	}
	sort.Strings(techniques)

	fmt.Println("\nMITRE ATT&CK Coverage")
	fmt.Println(strings.Repeat("-", 40))
	if len(techniques) == 0 {
		fmt.Println("(no techniques mapped)")
	}
	for _, t := range techniques {
		fmt.Printf("  %-10s %s\n", t, MitreName(t))
	}

	timeline := make([]Finding, len(all))
	copy(timeline, all)
	sort.Slice(timeline, func(i, j int) bool { return timeline[i].Timestamp.Before(timeline[j].Timestamp) })

	fmt.Println("\nTimeline")
	fmt.Println(strings.Repeat("-", 40))
	for _, f := range timeline {
		fmt.Printf("  %s  [%-10s] %-25s %s\n", f.Timestamp.Format("15:04:05"), f.Module, f.Subject, f.Title)
	}

	fmt.Println("\nRecommendation")
	fmt.Println(strings.Repeat("-", 40))
	for _, r := range recommendationsFor(techniqueSet) {
		fmt.Println("  - " + r)
	}
	fmt.Println()
}
