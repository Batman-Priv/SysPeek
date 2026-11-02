package modules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type ransomwareRule struct {
	binary  string
	pattern *regexp.Regexp
	label   string
	mitre   string
}

var ransomwareRules = []ransomwareRule{
	{"vssadmin.exe", regexp.MustCompile(`(?i)delete\s+shadows`), "Shadow copy deletion via vssadmin", "T1490"},
	{"wmic.exe", regexp.MustCompile(`(?i)shadowcopy\s+delete`), "Shadow copy deletion via WMIC", "T1490"},
	{"wbadmin.exe", regexp.MustCompile(`(?i)delete\s+(catalog|systemstatebackup)`), "Backup catalog/system-state deletion via wbadmin", "T1490"},
	{"bcdedit.exe", regexp.MustCompile(`(?i)recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures`), "Boot recovery disabled via bcdedit", "T1490"},
	{"cipher.exe", regexp.MustCompile(`(?i)/w:`), "Free-space wipe via cipher (anti-forensics)", "T1070.004"},
	{"powershell.exe", regexp.MustCompile(`(?i)(get-wmiobject|get-ciminstance)\s+win32_shadowcopy.*remove`), "Shadow copy deletion via PowerShell/WMI", "T1490"},
	{"fsutil.exe", regexp.MustCompile(`(?i)usn\s+deletejournal`), "USN journal deletion (anti-forensics)", "T1070"},
}

func GetRansomwareHunterFindings() [][]string {
	var results [][]string

	procs, err := fetchProcessListWMI()
	if err != nil {
		results = append(results, []string{"Ransomware Hunt", "Error", "Could not enumerate processes: " + err.Error()})
		return results
	}

	byPID := make(map[int]winProcess, len(procs))
	for _, p := range procs {
		byPID[p.ProcessId] = p
	}

	for _, p := range procs {
		lowerName := strings.ToLower(p.Name)
		for _, rule := range ransomwareRules {
			if lowerName != rule.binary || !rule.pattern.MatchString(p.CommandLine) {
				continue
			}
			chain := buildChain(p.ProcessId, byPID)
			cmdline := p.CommandLine
			if len(cmdline) > 160 {
				cmdline = cmdline[:160] + "..."
			}
			results = append(results, []string{chain, rule.label, cmdline})
			RegisterFinding("ransomware-hunt", fmt.Sprintf("%s (PID:%d)", p.Name, p.ProcessId), rule.label, 85, rule.mitre)
			break
		}
	}

	countLines := psLines(`(Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue | Measure-Object).Count`)
	if len(countLines) > 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(countLines[0])); err == nil {
			results = append(results, []string{"Shadow Copies", "Current Count", strconv.Itoa(n)})
		}
	}

	if len(results) == 0 {
		results = append(results, []string{"No ransomware precursor activity found", "Clean", "No shadow-copy/backup deletion or anti-forensics commands observed"})
	}

	return results
}
