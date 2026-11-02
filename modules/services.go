package modules

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func GetServices() [][]string {
	var results [][]string

	if runtime.GOOS == "windows" {
		scOut, _ := exec.Command("cmd", "/c", "sc", "query", "state=all", "|", "findstr", "SERVICE_NAME").Output()
		lines := strings.Split(string(scOut), "\n")
		var services []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "SERVICE_NAME:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					services = append(services, strings.TrimSpace(parts[1]))
				}
			}
		}
		if len(services) > 0 {
			results = append(results, []string{"Services", "Total Services", strconv.Itoa(len(services))})
			if len(services) > 20 {
				results = append(results, []string{"Services", "Service List", strings.Join(services[:20], ", ") + "..."})
			} else {
				results = append(results, []string{"Services", "Service List", strings.Join(services, ", ")})
			}
		}

		scRunning, _ := exec.Command("cmd", "/c", "sc", "query", "state=all", "|", "findstr", "RUNNING").Output()
		runningCount := strings.Count(string(scRunning), "RUNNING")
		results = append(results, []string{"Services", "Running Services", strconv.Itoa(runningCount)})

		scheduledTasks, _ := exec.Command("cmd", "/c", "schtasks", "/query", "/fo", "list", "|", "findstr", "TaskName").Output()
		taskLines := strings.Split(string(scheduledTasks), "\n")
		var tasks []string
		for _, line := range taskLines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "TaskName:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					taskName := strings.TrimSpace(parts[1])
					if taskName != "" {
						tasks = append(tasks, taskName)
					}
				}
			}
		}
		if len(tasks) > 0 {
			results = append(results, []string{"Scheduled Tasks", "Total Tasks", strconv.Itoa(len(tasks))})
			if len(tasks) > 20 {
				results = append(results, []string{"Scheduled Tasks", "Task List", strings.Join(tasks[:20], ", ") + "..."})
			} else {
				results = append(results, []string{"Scheduled Tasks", "Task List", strings.Join(tasks, ", ")})
			}
		}

	} else if runtime.GOOS == "linux" {
		systemdOut, _ := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager").Output()
		lines := strings.Split(string(systemdOut), "\n")
		var services []string
		for _, line := range lines {
			if strings.Contains(line, ".service") && !strings.Contains(line, "LOAD") && !strings.Contains(line, "UNIT") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					services = append(services, parts[0])
				}
			}
		}
		if len(services) > 0 {
			results = append(results, []string{"Services", "Total Services", strconv.Itoa(len(services))})
			if len(services) > 20 {
				results = append(results, []string{"Services", "Service List", strings.Join(services[:20], ", ") + "..."})
			} else {
				results = append(results, []string{"Services", "Service List", strings.Join(services, ", ")})
			}
		}

		cronOut, _ := exec.Command("crontab", "-l").Output()
		if len(cronOut) > 0 {
			cronLines := strings.Split(string(cronOut), "\n")
			var cronJobs []string
			for _, line := range cronLines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					cronJobs = append(cronJobs, line)
				}
			}
			if len(cronJobs) > 0 {
				results = append(results, []string{"Cron Jobs", "Total Jobs", strconv.Itoa(len(cronJobs))})
				if len(cronJobs) > 10 {
					results = append(results, []string{"Cron Jobs", "Job List", strings.Join(cronJobs[:10], " | ")})
				} else {
					results = append(results, []string{"Cron Jobs", "Job List", strings.Join(cronJobs, " | ")})
				}
			}
		}

		systemCron, _ := exec.Command("ls", "/etc/cron.d/").Output()
		if len(systemCron) > 0 {
			cronFiles := strings.TrimSpace(string(systemCron))
			if cronFiles != "" {
				results = append(results, []string{"Cron Jobs", "System Cron Files", cronFiles})
			}
		}
	}

	return results
}