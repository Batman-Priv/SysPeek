package modules

import (
	"os/exec"
	"runtime"
	"strings"
)

func GetLogsInfo() [][]string {
	var results [][]string

	if runtime.GOOS == "windows" {
		systemEvents, _ := exec.Command("cmd", "/c", "powershell", "-Command", "Get-EventLog -LogName System -Newest 10 | Select-Object TimeGenerated,EntryType,Source,EventID,Message").Output()
		systemLines := strings.Split(string(systemEvents), "\n")
		var sysEvents []string
		for _, line := range systemLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "TimeGenerated") && !strings.Contains(line, "----") && !strings.Contains(line, "System") {
				fields := strings.Fields(line)
				if len(fields) > 3 {
					eventType := ""
					if len(fields) >= 2 {
						eventType = fields[1]
					}
					if eventType == "Error" || eventType == "Warning" {
						sysEvents = append(sysEvents, line)
					}
				}
			}
		}
		if len(sysEvents) > 0 {
			results = append(results, []string{"Event Logs", "Critical Events (Last 10)", strings.Join(sysEvents[:5], " | ")})
		} else {
			results = append(results, []string{"Event Logs", "Status", "No critical events found"})
		}

		securityEvents, _ := exec.Command("cmd", "/c", "powershell", "-Command", "Get-EventLog -LogName Security -Newest 5 | Select-Object TimeGenerated,EntryType,EventID,Message").Output()
		securityLines := strings.Split(string(securityEvents), "\n")
		var secEvents []string
		for _, line := range securityLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "TimeGenerated") && !strings.Contains(line, "----") {
				secEvents = append(secEvents, line)
			}
		}
		if len(secEvents) > 0 {
			results = append(results, []string{"Security Logs", "Recent Events", strings.Join(secEvents[:3], " | ")})
		}

		applicationEvents, _ := exec.Command("cmd", "/c", "powershell", "-Command", "Get-EventLog -LogName Application -Newest 5 | Select-Object TimeGenerated,EntryType,Source,Message").Output()
		appLines := strings.Split(string(applicationEvents), "\n")
		var appEvents []string
		for _, line := range appLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "TimeGenerated") && !strings.Contains(line, "----") {
				appEvents = append(appEvents, line)
			}
		}
		if len(appEvents) > 0 {
			results = append(results, []string{"Application Logs", "Recent Events", strings.Join(appEvents[:3], " | ")})
		}

		historyOut, _ := exec.Command("cmd", "/c", "powershell", "-Command", "Get-History | Select-Object -Last 5").Output()
		historyLines := strings.Split(string(historyOut), "\n")
		var history []string
		for _, line := range historyLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "Id") && !strings.Contains(line, "----") {
				history = append(history, line)
			}
		}
		if len(history) > 0 {
			results = append(results, []string{"Command History", "PowerShell (Last 5)", strings.Join(history, " | ")})
		}

		startupEvents, _ := exec.Command("cmd", "/c", "powershell", "-Command", "Get-WinEvent -FilterHashtable @{LogName='System'; ID=12,13,14,41,1074,6005,6006,6008,6009} -MaxEvents 5 | Select-Object TimeCreated,Id,Message").Output()
		startupLines := strings.Split(string(startupEvents), "\n")
		var startup []string
		for _, line := range startupLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "TimeCreated") && !strings.Contains(line, "----") {
				startup = append(startup, line)
			}
		}
		if len(startup) > 0 {
			results = append(results, []string{"System Logs", "Startup/Shutdown Events", strings.Join(startup[:3], " | ")})
		}

	} else if runtime.GOOS == "linux" {
		syslog, _ := exec.Command("tail", "-n", "10", "/var/log/syslog").Output()
		if len(syslog) > 0 {
			sysLines := strings.Split(string(syslog), "\n")
			var critical []string
			for _, line := range sysLines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "error") || strings.Contains(line, "fail") || strings.Contains(line, "critical") {
					critical = append(critical, line)
				}
			}
			if len(critical) > 0 {
				results = append(results, []string{"System Logs", "Critical Events", strings.Join(critical[:3], " | ")})
			} else {
				results = append(results, []string{"System Logs", "Status", "No critical events found"})
			}
		}

		authLog, _ := exec.Command("tail", "-n", "5", "/var/log/auth.log").Output()
		if len(authLog) > 0 {
			authLines := strings.Split(string(authLog), "\n")
			var authEvents []string
			for _, line := range authLines {
				line = strings.TrimSpace(line)
				if line != "" && (strings.Contains(line, "Accepted") || strings.Contains(line, "Failed") || strings.Contains(line, "Invalid")) {
					authEvents = append(authEvents, line)
				}
			}
			if len(authEvents) > 0 {
				results = append(results, []string{"Security Logs", "Recent Auth Events", strings.Join(authEvents[:3], " | ")})
			}
		}

		kernelLog, _ := exec.Command("dmesg", "|", "tail", "-n", "5").Output()
		if len(kernelLog) > 0 {
			results = append(results, []string{"Kernel Logs", "Recent Messages", strings.TrimSpace(string(kernelLog))})
		}

		historyOut, _ := exec.Command("bash", "-c", "tail -n 5 ~/.bash_history").Output()
		if len(historyOut) > 0 {
			historyLines := strings.Split(string(historyOut), "\n")
			var history []string
			for _, line := range historyLines {
				line = strings.TrimSpace(line)
				if line != "" {
					history = append(history, line)
				}
			}
			if len(history) > 0 {
				results = append(results, []string{"Command History", "Recent (Last 5)", strings.Join(history, " | ")})
			}
		}

		sudoLog, _ := exec.Command("tail", "-n", "3", "/var/log/sudo.log").Output()
		if len(sudoLog) > 0 {
			results = append(results, []string{"Security Logs", "Recent Sudo Events", strings.TrimSpace(string(sudoLog))})
		}
	}

	return results
}
