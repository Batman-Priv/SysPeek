package modules

import (
	"fmt"
	"regexp"
	"strings"
)

type lsassRule struct {
	binary  string 
	pattern *regexp.Regexp
	label   string
	mitre   string
	sev     int
}

var lsassRules = []lsassRule{
	{"rundll32.exe", regexp.MustCompile(`(?i)comsvcs\.dll.*minidump`), "LSASS dump via rundll32/comsvcs.dll MiniDump technique", "T1003.001", 95},
	{"procdump.exe", regexp.MustCompile(`(?i)lsass`), "LSASS dump via ProcDump", "T1003.001", 90},
	{"procdump64.exe", regexp.MustCompile(`(?i)lsass`), "LSASS dump via ProcDump", "T1003.001", 90},
	{"reg.exe", regexp.MustCompile(`(?i)save\s+hklm\\(sam|security|system)`), "Registry hive save (SAM/SECURITY/SYSTEM) - offline credential extraction precursor", "T1003.002", 85},
	{"taskmgr.exe", regexp.MustCompile(`(?i)$^`), "", "", 0}, 
	{"mimikatz.exe", regexp.MustCompile(`.*`), "Known credential-dumping tool executed (matched by filename - trivially renamed by an attacker, treat as low-confidence on its own)", "T1003.001", 70},
	{"pypykatz.exe", regexp.MustCompile(`.*`), "Known credential-dumping tool executed (matched by filename)", "T1003.001", 65},
	{"nanodump.exe", regexp.MustCompile(`.*`), "Known credential-dumping tool executed (matched by filename)", "T1003.001", 70},
	{"lazagne.exe", regexp.MustCompile(`.*`), "Known credential-harvesting tool executed (matched by filename)", "T1003", 65},
}

func GetLSASSFindings() [][]string {
	var results [][]string

	procs, err := fetchProcessListWMI()
	if err != nil {
		results = append(results, []string{"LSASS Hunt", "Error", "Could not enumerate processes: " + err.Error()})
		return results
	}

	byPID := make(map[int]winProcess, len(procs))
	for _, p := range procs {
		byPID[p.ProcessId] = p
	}

	allowSet := map[string]bool{}
	for _, a := range LoadConfig().LsassAllowlist {
		allowSet[strings.ToLower(a)] = true
	}

	for _, p := range procs {
		lowerName := strings.ToLower(p.Name)
		if allowSet[lowerName] {
			continue
		}
		for _, rule := range lsassRules {
			if rule.mitre == "" || lowerName != rule.binary || !rule.pattern.MatchString(p.CommandLine) {
				continue
			}
			chain := buildChain(p.ProcessId, byPID)
			cmdline := p.CommandLine
			if len(cmdline) > 160 {
				cmdline = cmdline[:160] + "..."
			}
			results = append(results, []string{chain, rule.label, cmdline})
			RegisterFinding("lsass", fmt.Sprintf("%s (PID:%d)", p.Name, p.ProcessId), rule.label, rule.sev, rule.mitre)
			break
		}
	}

	if len(results) == 0 {
		results = append(results, []string{
			"No LSASS dumping signatures found", "Clean",
			"Command-line/filename check only - pair with Sysmon Event ID 10 for handle-level visibility",
		})
	}

	return results
}
