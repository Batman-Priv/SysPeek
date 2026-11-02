package modules

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type winProcess struct {
	ProcessId       int    `json:"ProcessId"`
	ParentProcessId int    `json:"ParentProcessId"`
	Name            string `json:"Name"`
	CommandLine     string `json:"CommandLine"`
}

var lolbinNames = map[string]bool{
	"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
	"certutil.exe": true, "bitsadmin.exe": true, "wmic.exe": true,
	"installutil.exe": true, "cmstp.exe": true, "msbuild.exe": true,
	"wscript.exe": true, "cscript.exe": true, "powershell.exe": true,
	"pwsh.exe": true, "regasm.exe": true, "regsvcs.exe": true,
	"forfiles.exe": true, "psexec.exe": true, "psexec64.exe": true,
}

type lolbinRule struct {
	pattern *regexp.Regexp
	label   string
}

var lolbinPatterns = map[string][]lolbinRule{
	"mshta.exe": {
		{regexp.MustCompile(`(?i)https?://`), "mshta fetching a remote HTA"},
		{regexp.MustCompile(`(?i)vbscript:|javascript:`), "mshta running inline script"},
	},
	"rundll32.exe": {
		{regexp.MustCompile(`(?i)javascript:`), "rundll32 running inline JavaScript"},
		{regexp.MustCompile(`(?i)url\.dll.*openurl|shdocvw\.dll`), "rundll32 abusing URL/shdocvw handler"},
		{regexp.MustCompile(`(?i)\\appdata\\|\\temp\\|\\downloads\\`), "rundll32 loading a DLL from a user-writable path"},
	},
	"regsvr32.exe": {
		{regexp.MustCompile(`(?i)/i:https?://`), "regsvr32 'Squiblydoo' - registering a remote scriptlet"},
		{regexp.MustCompile(`(?i)scrobj\.dll`), "regsvr32 loading scrobj.dll (scriptlet execution)"},
	},
	"certutil.exe": {
		{regexp.MustCompile(`(?i)-urlcache|-verifyctl`), "certutil used to fetch a remote file"},
		{regexp.MustCompile(`(?i)-decode|-decodehex`), "certutil used to decode a payload"},
	},
	"bitsadmin.exe": {
		{regexp.MustCompile(`(?i)/transfer`), "bitsadmin used to download a file (BITS jobs)"},
	},
	"wmic.exe": {
		{regexp.MustCompile(`(?i)process\s+call\s+create`), "wmic used to spawn a process remotely/locally"},
		{regexp.MustCompile(`(?i)/format:https?://|/format:.*\.xsl`), "wmic loading a remote/xsl format (bypass technique)"},
	},
	"powershell.exe": {
		{regexp.MustCompile(`(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}`), "PowerShell running a base64-encoded command"},
		{regexp.MustCompile(`(?i)-w(indowstyle)?\s+hidden`), "PowerShell launched with a hidden window"},
		{regexp.MustCompile(`(?i)downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-expression|\biex\b`), "PowerShell downloading/executing remote content"},
		{regexp.MustCompile(`(?i)-nop\b.*-noni\b|bypass\s+-c`), "PowerShell run with logging/profile evasion flags"},
	},
	"pwsh.exe": {
		{regexp.MustCompile(`(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}`), "PowerShell (pwsh) running a base64-encoded command"},
	},
	"cmstp.exe": {
		{regexp.MustCompile(`(?i)/s\s+\S+\.inf`), "cmstp silently installing an INF (UAC bypass technique)"},
	},
	"installutil.exe": {
		{regexp.MustCompile(`(?i)/logfile=\s*/logtoconsole=false`), "InstallUtil run with logging suppressed"},
	},
	"regasm.exe": {
		{regexp.MustCompile(`(?i)\.dll$`), "Regasm loading an arbitrary DLL outside normal COM registration flow"},
	},
	"regsvcs.exe": {
		{regexp.MustCompile(`(?i)\.dll$`), "Regsvcs loading an arbitrary DLL outside normal COM registration flow"},
	},
	"wscript.exe": {
		{regexp.MustCompile(`(?i)\\appdata\\|\\temp\\|\\downloads\\`), "wscript running a script from a user-writable path"},
	},
	"cscript.exe": {
		{regexp.MustCompile(`(?i)\\appdata\\|\\temp\\|\\downloads\\`), "cscript running a script from a user-writable path"},
	},
	"forfiles.exe": {
		{regexp.MustCompile(`(?i)/c\s+.*cmd`), "forfiles proxying execution through cmd"},
	},
	"psexec.exe":   {{regexp.MustCompile(`.*`), "PsExec-style remote execution tool present"}},
	"psexec64.exe": {{regexp.MustCompile(`.*`), "PsExec-style remote execution tool present"}},
}

var lolbinMitre = map[string]string{
	"mshta.exe": "T1218.005", "rundll32.exe": "T1218.011", "regsvr32.exe": "T1218.010",
	"certutil.exe": "T1105", "bitsadmin.exe": "T1197", "wmic.exe": "T1047",
	"powershell.exe": "T1059.001", "pwsh.exe": "T1059.001",
	"wscript.exe": "T1059.005", "cscript.exe": "T1059.005",
	"installutil.exe": "T1218.004", "cmstp.exe": "T1218.003",
	"msbuild.exe": "T1127", "regasm.exe": "T1218.009", "regsvcs.exe": "T1218.009",
}

func fetchProcessListWMI() ([]winProcess, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress").Output()
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, fmt.Errorf("empty process list")
	}

	if trimmed[0] != '[' {
		trimmed = "[" + trimmed + "]"
	}

	var procs []winProcess
	if err := json.Unmarshal([]byte(trimmed), &procs); err != nil {
		return nil, err
	}
	return procs, nil
}

func buildChain(pid int, byPID map[int]winProcess) string {
	var chain []string
	seen := map[int]bool{}
	current := pid
	for i := 0; i < 6; i++ {
		p, ok := byPID[current]
		if !ok || seen[current] {
			break
		}
		seen[current] = true
		chain = append([]string{p.Name}, chain...)
		if p.ParentProcessId == 0 || p.ParentProcessId == current {
			break
		}
		current = p.ParentProcessId
	}
	return strings.Join(chain, " -> ")
}

func GetLOLBinFindings() [][]string {
	var results [][]string

	procs, err := fetchProcessListWMI()
	if err != nil {
		results = append(results, []string{"LOLBin Scan", "Error", "Could not enumerate process command lines: " + err.Error()})
		return results
	}

	byPID := make(map[int]winProcess, len(procs))
	for _, p := range procs {
		byPID[p.ProcessId] = p
	}

	for _, p := range procs {
		lowerName := strings.ToLower(p.Name)
		if !lolbinNames[lowerName] {
			continue
		}

		rules, ok := lolbinPatterns[lowerName]
		if !ok {
			continue
		}

		for _, rule := range rules {
			if !rule.pattern.MatchString(p.CommandLine) {
				continue
			}

			chain := buildChain(p.ProcessId, byPID)
			mitre := lolbinMitre[lowerName]
			cmdline := p.CommandLine
			if len(cmdline) > 160 {
				cmdline = cmdline[:160] + "..."
			}

			subject := fmt.Sprintf("%s (PID:%d)", p.Name, p.ProcessId)
			title := fmt.Sprintf("%s [%s]", rule.label, mitre)

			results = append(results, []string{chain, MitreName(mitre), cmdline})
			RegisterFinding("lolbin", subject, rule.label, 55, mitre)
			_ = title
			break
		}
	}

	if len(results) == 0 {
		results = append(results, []string{"No suspicious LOLBin activity found", "Clean", "No matching command-line patterns"})
	}

	return results
}
