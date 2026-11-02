package modules

import (
	"os/exec"
	"runtime"
	"strings"
)

func DetectEDR() [][]string {
	var results [][]string
	var detected []string

	if runtime.GOOS == "windows" {
		processes, _ := exec.Command("tasklist", "/fo", "csv", "/nh").Output()
		lines := strings.Split(string(processes), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "crowdstrike") ||
				strings.Contains(strings.ToLower(line), "sentinel") ||
				strings.Contains(strings.ToLower(line), "carbonblack") ||
				strings.Contains(strings.ToLower(line), "cylance") ||
				strings.Contains(strings.ToLower(line), "defender") ||
				strings.Contains(strings.ToLower(line), "symantec") ||
				strings.Contains(strings.ToLower(line), "mcafee") ||
				strings.Contains(strings.ToLower(line), "trendmicro") ||
				strings.Contains(strings.ToLower(line), "kaspersky") ||
				strings.Contains(strings.ToLower(line), "eset") {
				detected = append(detected, strings.TrimSpace(line))
			}
		}
	} else if runtime.GOOS == "linux" {
		psOutput, _ := exec.Command("ps", "aux").Output()
		lines := strings.Split(string(psOutput), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "falcon") ||
				strings.Contains(strings.ToLower(line), "sentinel") ||
				strings.Contains(strings.ToLower(line), "cb") ||
				strings.Contains(strings.ToLower(line), "cylance") ||
				strings.Contains(strings.ToLower(line), "clamav") ||
				strings.Contains(strings.ToLower(line), "sophos") ||
				strings.Contains(strings.ToLower(line), "trend") {
				detected = append(detected, strings.TrimSpace(line))
			}
		}
	}

	if len(detected) == 0 {
		results = append(results, []string{"No EDR/AV Detected", "N/A", "System appears clean"})
	} else {
		for _, item := range detected {
			status := "Running"
			details := "Process detected"
			if strings.Contains(strings.ToLower(item), "defender") && runtime.GOOS == "windows" {
				status = "Active"
				details = "Windows Defender is active"
			}
			results = append(results, []string{extractProductName(item), status, details})
		}
	}
	return results
}

func extractProductName(entry string) string {
	parts := strings.Fields(entry)
	if len(parts) > 0 {
		for _, p := range parts {
			if strings.Contains(strings.ToLower(p), ".exe") || strings.Contains(strings.ToLower(p), "falcon") {
				return strings.TrimSuffix(p, ".exe")
			}
		}
		return parts[0]
	}
	return "Unknown"
}