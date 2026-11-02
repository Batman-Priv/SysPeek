package modules

import (
	"fmt"
	"regexp"
	"strings"
)

var exePathRe = regexp.MustCompile(`(?i)"([^"]+\.exe)"|([A-Za-z]:\\[^\s"]+\.exe)`)

func extractExePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if m := exePathRe.FindStringSubmatch(raw); m != nil {
		if m[1] != "" {
			return m[1]
		}
		if m[2] != "" {
			return m[2]
		}
	}
	fields := strings.Fields(raw)
	if len(fields) > 0 && strings.Contains(fields[0], `\`) {
		return strings.Trim(fields[0], `"`)
	}
	return ""
}

func autorunsServices() []string {
	return psLines(`Get-CimInstance Win32_Service | Where-Object {$_.StartMode -ne 'Disabled'} | ForEach-Object { "$($_.Name)|$($_.PathName)" }`)
}

func autorunsTasks() []string {
	return psLines(`Get-ScheduledTask -EA SilentlyContinue | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object { $act = $_.Actions | Select-Object -First 1; "$($_.TaskName)|$($act.Execute) $($act.Arguments)" }`)
}

func autorunsRunKeys() []string {
	return psLines(`$paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'); foreach ($p in $paths) { if (Test-Path $p) { (Get-Item $p).Property | ForEach-Object { $val = (Get-ItemProperty -Path $p -Name $_).$_; "$_|$val" } } }`)
}

func autorunsStartupFolders() []string {
	return psLines(`$dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:AppData\Microsoft\Windows\Start Menu\Programs\StartUp"); foreach ($d in $dirs) { if (Test-Path $d) { Get-ChildItem $d -File -EA SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.FullName)" } } }`)
}


func GetAutorunsInventory() [][]string {
	var results [][]string

	sections := []struct {
		category string
		lines    []string
		mitre    string
	}{
		{"Service", autorunsServices(), "T1543.003"},
		{"Scheduled Task", autorunsTasks(), "T1053.005"},
		{"Run Key", autorunsRunKeys(), "T1547.001"},
		{"Startup Folder", autorunsStartupFolders(), "T1547.001"},
	}

	for _, sec := range sections {
		for _, line := range sec.lines {
			parts := strings.SplitN(line, "|", 2)
			if len(parts) != 2 {
				continue
			}
			name, raw := parts[0], strings.TrimSpace(parts[1])
			if name == "" {
				continue
			}

			path := extractExePath(raw)
			status := "Unresolved"
			sev := 0

			if path != "" {
				sig := verifySignature(path)
				switch {
				case sig.Tampered:
					status = "TAMPERED"
					sev = 90
				case !sig.Signed:
					status = "Unsigned"
					sev = 20
				default:
					status = "Signed"
				}
			}

			display := raw
			if len(display) > 100 {
				display = display[:100] + "..."
			}
			results = append(results, []string{sec.category, name, status, display})

			if sev > 0 {
				RegisterFinding("autoruns", name,
					fmt.Sprintf("%s autorun entry is %s: %s", sec.category, strings.ToLower(status), display),
					sev, sec.mitre)
			}
		}
	}

	if len(results) == 0 {
		results = append(results, []string{"No autorun entries found", "", "", ""})
	}

	return results
}
