package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type BaselineSnapshot struct {
	CapturedAt time.Time `json:"captured_at"`
	Services   []string  `json:"services"`
	Tasks      []string  `json:"tasks"`
	RunKeys    []string  `json:"run_keys"`
	Drivers    []string  `json:"drivers"`
}

func baselinePath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = "."
	}
	dir := filepath.Join(base, "SysPeek")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		
		return "syspeek_baseline.json"
	}
	return filepath.Join(dir, "baseline.json")
}

func psLines(command string) []string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", command).Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}
	sort.Strings(lines)
	return lines
}

func captureSnapshot() BaselineSnapshot {
	return BaselineSnapshot{
		CapturedAt: time.Now(),
		Services: psLines(
			`Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name)|$($_.PathName)|$($_.StartMode)|$($_.State)" }`),
		Tasks: psLines(
			`Get-ScheduledTask | ForEach-Object { "$($_.TaskName)|$($_.TaskPath)|$($_.State)" }`),
		RunKeys: psLines(
			`$paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'); foreach ($p in $paths) { if (Test-Path $p) { Get-Item $p | Select-Object -ExpandProperty Property | ForEach-Object { $val = (Get-ItemProperty -Path $p -Name $_).$_ ; "$p|$_|$val" } } }`),
		Drivers: psLines(
			`Get-CimInstance Win32_SystemDriver | ForEach-Object { "$($_.Name)|$($_.PathName)|$($_.State)" }`),
	}
}

func CaptureBaseline() (string, error) {
	snap := captureSnapshot()
	path := baselinePath()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func loadBaseline() (BaselineSnapshot, string, error) {
	path := baselinePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return BaselineSnapshot{}, path, err
	}
	var snap BaselineSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return BaselineSnapshot{}, path, err
	}
	return snap, path, nil
}

func diffSet(prev, next []string) (added, removed []string) {
	prevSet := make(map[string]bool, len(prev))
	for _, p := range prev {
		prevSet[p] = true
	}
	nextSet := make(map[string]bool, len(next))
	for _, n := range next {
		nextSet[n] = true
	}
	for _, n := range next {
		if !prevSet[n] {
			added = append(added, n)
		}
	}
	for _, p := range prev {
		if !nextSet[p] {
			removed = append(removed, p)
		}
	}
	return
}

func DiffBaseline() [][]string {
	var results [][]string

	prev, path, err := loadBaseline()
	if err != nil {
		results = append(results, []string{"Baseline", "Error",
			fmt.Sprintf("No baseline found at %s - run with --baseline first", path)})
		return results
	}

	next := captureSnapshot()

	categories := []struct {
		name   string
		prev   []string
		next   []string
		mitre  string
		weight int
	}{
		{"Service", prev.Services, next.Services, "T1543.003", 45},
		{"Scheduled Task", prev.Tasks, next.Tasks, "T1053.005", 45},
		{"Run Key", prev.RunKeys, next.RunKeys, "T1547.001", 40},
		{"Driver", prev.Drivers, next.Drivers, "T1547.006", 50},
	}

	anyChange := false
	for _, cat := range categories {
		added, removed := diffSet(cat.prev, cat.next)
		for _, a := range added {
			anyChange = true
			results = append(results, []string{cat.name, "ADDED", a})
			RegisterFinding("baseline", a, fmt.Sprintf("New %s since last baseline", strings.ToLower(cat.name)), cat.weight, cat.mitre)
		}
		for _, r := range removed {
			anyChange = true
			results = append(results, []string{cat.name, "removed", r})
		}
	}

	if !anyChange {
		results = append(results, []string{"Baseline", "No changes", fmt.Sprintf("System matches baseline captured %s", prev.CapturedAt.Format(time.RFC1123))})
	}

	return results
}
