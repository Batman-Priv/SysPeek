package modules

import (
	"sync"
	"time"
)

type Finding struct {
	Timestamp time.Time
	Module    string 
	Subject   string 
	Title     string 
	Severity  int    
	Mitre     []string
}

var (
	findingsMu sync.Mutex
	findings   []Finding
)

func RegisterFinding(module, subject, title string, severity int, mitre ...string) {
	findingsMu.Lock()
	defer findingsMu.Unlock()
	findings = append(findings, Finding{
		Timestamp: time.Now(),
		Module:    module,
		Subject:   subject,
		Title:     title,
		Severity:  severity,
		Mitre:     mitre,
	})
}

func AllFindings() []Finding {
	findingsMu.Lock()
	defer findingsMu.Unlock()
	out := make([]Finding, len(findings))
	copy(out, findings)
	return out
}

func ResetFindings() {
	findingsMu.Lock()
	defer findingsMu.Unlock()
	findings = nil
}

var mitreNames = map[string]string{
	"T1055":     "Process Injection",
	"T1055.001": "Dynamic-link Library Injection",
	"T1027":     "Obfuscated/Compressed Files or Information",
	"T1036":     "Masquerading",
	"T1036.001": "Invalid Code Signature",
	"T1553.002": "Subvert Trust Controls: Code Signing",
	"T1574.001": "DLL Search Order Hijacking",
	"T1105":     "Ingress Tool Transfer",
	"T1197":     "BITS Jobs",
	"T1047":     "Windows Management Instrumentation",
	"T1127":     "Trusted Developer Utilities Proxy Execution",
	"T1218":     "System Binary Proxy Execution",
	"T1218.003": "CMSTP",
	"T1218.004": "InstallUtil",
	"T1218.005": "Mshta",
	"T1218.009": "Regsvcs/Regasm",
	"T1218.010": "Regsvr32",
	"T1218.011": "Rundll32",
	"T1059.001": "PowerShell",
	"T1059.005": "Visual Basic (wscript/cscript)",
	"T1547.001": "Registry Run Keys / Startup Folder",
	"T1543.003": "Create or Modify System Process: Windows Service",
	"T1053.005": "Scheduled Task",
	"T1547.006": "Kernel Modules and Extensions",
	"T1546.003": "Windows Management Instrumentation Event Subscription",
	"T1546.008": "Accessibility Features",
	"T1546.010": "AppInit DLLs",
	"T1546.012": "Image File Execution Options Injection",
	"T1547.004": "Winlogon Helper DLL",
	"T1547.005": "Security Support Provider",
	"T1553.006": "Code Signing Policy Modification",
	"T1490":     "Inhibit System Recovery",
	"T1070":     "Indicator Removal",
	"T1071":     "Application Layer Protocol",
	"T1003":     "OS Credential Dumping",
	"T1003.001": "LSASS Memory",
	"T1003.002": "Security Account Manager",
}

func MitreName(id string) string {
	if n, ok := mitreNames[id]; ok {
		return n
	}
	return id
}
