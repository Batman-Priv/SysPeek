package modules

import (
	"os/exec"
	"runtime"
	"strings"
)

func GetAntivirusInfo() [][]string {
	var results [][]string

	if runtime.GOOS == "windows" {
		defenderOut, _ := exec.Command("cmd", "/c", "powershell", "-Command", "Get-MpComputerStatus").Output()
		lines := strings.Split(string(defenderOut), "\n")
		
		var defenderStatus string
		var realtimeProtection string
		
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "AntivirusEnabled") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					if strings.Contains(parts[1], "True") {
						defenderStatus = "Enabled"
					} else {
						defenderStatus = "Disabled"
					}
				}
			}
			if strings.Contains(line, "RealTimeProtectionEnabled") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					if strings.Contains(parts[1], "True") {
						realtimeProtection = "Enabled"
					} else {
						realtimeProtection = "Disabled"
					}
				}
			}
		}
		
		if defenderStatus != "" {
			results = append(results, []string{"Antivirus", "Windows Defender", defenderStatus})
		}
		if realtimeProtection != "" {
			results = append(results, []string{"Antivirus", "Real-time Protection", realtimeProtection})
		}

		wscOut, _ := exec.Command("cmd", "/c", "wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntivirusProduct", "get", "displayName,productState").Output()
		lines = strings.Split(string(wscOut), "\n")
		var avProducts []string
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line != "" {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					productName := strings.Join(fields[:len(fields)-1], " ")
					avProducts = append(avProducts, productName)
				}
			}
		}
		if len(avProducts) > 0 {
			results = append(results, []string{"Antivirus", "Installed AV", strings.Join(avProducts, ", ")})
		}

		firewallOut, _ := exec.Command("cmd", "/c", "netsh", "advfirewall", "show", "allprofiles").Output()
		firewallLines := strings.Split(string(firewallOut), "\n")
		for _, line := range firewallLines {
			if strings.Contains(line, "State") && strings.Contains(line, "Profile") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					profile := strings.TrimSpace(parts[0])
					state := strings.TrimSpace(parts[1])
					results = append(results, []string{"Firewall", profile, state})
				}
			}
		}

		uacOut, _ := exec.Command("cmd", "/c", "reg", "query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA").Output()
		uacLines := strings.Split(string(uacOut), "\n")
		for _, line := range uacLines {
			if strings.Contains(line, "EnableLUA") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					if strings.Contains(parts[2], "1") {
						results = append(results, []string{"Security", "UAC Status", "Enabled"})
					} else {
						results = append(results, []string{"Security", "UAC Status", "Disabled"})
					}
				}
			}
		}

	} else if runtime.GOOS == "linux" {
		psOut, _ := exec.Command("ps", "aux").Output()
		lines := strings.Split(string(psOut), "\n")
		
		var avProcesses []string
		avList := []string{"clamav", "sophos", "falcon", "sentinel", "osquery", "aide", "rkhunter", "chkrootkit"}
		
		for _, line := range lines {
			lowerLine := strings.ToLower(line)
			for _, av := range avList {
				if strings.Contains(lowerLine, av) {
					avProcesses = append(avProcesses, av)
				}
			}
		}
		
		if len(avProcesses) > 0 {
			results = append(results, []string{"Antivirus/Security", "Detected", strings.Join(avProcesses, ", ")})
		} else {
			results = append(results, []string{"Antivirus/Security", "Status", "No known AV detected"})
		}

		iptablesOut, _ := exec.Command("sudo", "iptables", "-L").Output()
		if len(iptablesOut) > 0 {
			results = append(results, []string{"Firewall", "IPtables", "Active"})
		} else {
			results = append(results, []string{"Firewall", "IPtables", "Inactive or no permission"})
		}
	}

	return results
}