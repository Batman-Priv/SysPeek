package modules

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func GetFileSystemInfo() [][]string {
	var results [][]string

	if runtime.GOOS == "windows" {
		sensitiveFiles := []string{
			"C:\\Windows\\System32\\drivers\\etc\\hosts",
			"C:\\Windows\\System32\\config\\SAM",
			"C:\\Windows\\System32\\config\\SECURITY",
			"C:\\Windows\\System32\\config\\SYSTEM",
			"C:\\Windows\\System32\\config\\SOFTWARE",
		}

		for _, file := range sensitiveFiles {
			if _, err := os.Stat(file); err == nil {
				perm, _ := os.Stat(file)
				results = append(results, []string{"Sensitive Files", file, perm.Mode().String()})
			} else {
				results = append(results, []string{"Sensitive Files", file, "Not Found"})
			}
		}

		recentFiles, _ := exec.Command("cmd", "/c", "powershell", "-Command", "Get-ChildItem -Path C:\\Users\\%USERNAME%\\Downloads -File | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name,LastWriteTime").Output()
		recentLines := strings.Split(string(recentFiles), "\n")
		var recentList []string
		for _, line := range recentLines[3:] {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "----") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					recentList = append(recentList, fields[0])
				}
			}
		}
		if len(recentList) > 0 {
			results = append(results, []string{"Recent Files", "Downloads", strings.Join(recentList, ", ")})
		}

	} else if runtime.GOOS == "linux" {
		sensitiveFiles := []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/etc/ssh/sshd_config",
			"/etc/hosts",
			"/root/.bash_history",
		}

		for _, file := range sensitiveFiles {
			if _, err := os.Stat(file); err == nil {
				perm, _ := os.Stat(file)
				results = append(results, []string{"Sensitive Files", file, perm.Mode().String()})
			} else {
				results = append(results, []string{"Sensitive Files", file, "Not Found"})
			}
		}

		recentFiles, _ := exec.Command("find", "/home", "-type", "f", "-mtime", "-1", "-printf", "%f\\n").Output()
		recentList := strings.Split(string(recentFiles), "\n")
		if len(recentList) > 0 && recentList[0] != "" {
			results = append(results, []string{"Recent Files", "Last 24h", strings.Join(recentList[:10], ", ")})
		}
	}

	return results
}
