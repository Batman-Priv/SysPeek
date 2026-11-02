package modules

import (
	"fmt"
	"strings"
)

var accessibilityTargets = map[string]bool{
	"sethc.exe": true, "utilman.exe": true, "osk.exe": true,
	"magnify.exe": true, "narrator.exe": true, "displayswitch.exe": true,
	"atbroker.exe": true,
}

var knownLsaPackages = map[string]bool{
	"": true, "kerberos": true, "msv1_0": true, "schannel": true,
	"wdigest": true, "tspkg": true, "pku2u": true, "negoexts": true,
	"livessp": true, "msv1_0.dll": true, "kerberos.dll": true,
}

func GetPersistenceFindings() [][]string {
	var results [][]string

	ifeoOut := psLines(`Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object { $d = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger; if ($d) { "$($_.PSChildName)|$d" } }`)
	for _, line := range ifeoOut {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		image, debugger := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		sev := 55
		mitre := "T1546.012"
		note := fmt.Sprintf("IFEO Debugger set for %s -> %s", image, debugger)
		if accessibilityTargets[image] {
			sev = 90
			mitre = "T1546.008"
			note = fmt.Sprintf("Accessibility-feature backdoor: %s Debugger hijacked to run %s", image, debugger)
		}
		results = append(results, []string{"IFEO Hijack", image, debugger})
		RegisterFinding("persistence", image, note, sev, mitre)
	}

	appInit := psLines(`$p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; $dll=(Get-ItemProperty -Path $p -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs; $load=(Get-ItemProperty -Path $p -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs; if ($dll -and $load -eq 1) { "$dll" }`)
	for _, dll := range appInit {
		results = append(results, []string{"AppInit_DLLs", "Enabled", dll})
		RegisterFinding("persistence", dll, "AppInit_DLLs is enabled and loads into every GUI process: "+dll, 65, "T1546.010")
	}

	winlogon := psLines(`$p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; "Shell|$((Get-ItemProperty -Path $p -Name Shell -EA SilentlyContinue).Shell)"; "Userinit|$((Get-ItemProperty -Path $p -Name Userinit -EA SilentlyContinue).Userinit)"`)
	for _, line := range winlogon {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], strings.TrimSpace(parts[1])
		lower := strings.ToLower(val)
		suspicious := false
		switch key {
		case "Shell":
			suspicious = val != "" && lower != "explorer.exe"
		case "Userinit":
			suspicious = val != "" && !strings.Contains(lower, "userinit.exe")
		}
		if suspicious {
			results = append(results, []string{"Winlogon Tampering", key, val})
			RegisterFinding("persistence", key, fmt.Sprintf("Winlogon %s modified from default: %s", key, val), 75, "T1547.004")
		}
	}

	lsaLines := psLines(`$p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; ((Get-ItemProperty -Path $p -Name 'Security Packages' -EA SilentlyContinue).'Security Packages' -join ','); ((Get-ItemProperty -Path $p -Name 'Authentication Packages' -EA SilentlyContinue).'Authentication Packages' -join ',')`)
	for _, line := range lsaLines {
		for _, pkg := range strings.Split(line, ",") {
			pkg = strings.TrimSpace(pkg)
			if pkg == "" {
				continue
			}
			if !knownLsaPackages[strings.ToLower(pkg)] {
				results = append(results, []string{"LSA Package", "Unrecognized", pkg})
				RegisterFinding("persistence", pkg, "Unrecognized LSA security/authentication package (possible credential-theft implant): "+pkg, 70, "T1547.005")
			}
		}
	}

	wmi := psLines(`Get-WmiObject -Namespace root\subscription -Class __EventFilter -EA SilentlyContinue | ForEach-Object { "Filter|$($_.Name)" }; Get-WmiObject -Namespace root\subscription -Class __EventConsumer -EA SilentlyContinue | ForEach-Object { "Consumer|$($_.Name)" }`)
	for _, line := range wmi {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		results = append(results, []string{"WMI Subscription", parts[0], parts[1]})
		RegisterFinding("persistence", parts[1], "WMI permanent event "+strings.ToLower(parts[0])+" present (review for legitimacy): "+parts[1], 35, "T1546.003")
	}

	if len(results) == 0 {
		results = append(results, []string{"No persistence indicators found", "Clean", "IFEO/AppInit/Winlogon/LSA/WMI all match expected defaults"})
	}

	return results
}
