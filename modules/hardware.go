package modules

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"os"
)

func GetHardwareInfo() [][]string {
	var results [][]string

	osInfo := fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)
	results = append(results, []string{"System", "Operating System", osInfo})
	results = append(results, []string{"System", "CPU Cores", strconv.Itoa(runtime.NumCPU())})

	if runtime.GOOS == "windows" {
		hostname, _ := exec.Command("hostname").Output()
		results = append(results, []string{"System", "Hostname", strings.TrimSpace(string(hostname))})

		osNameOut, _ := exec.Command("cmd", "/c", "wmic", "os", "get", "Caption").Output()
		lines := strings.Split(string(osNameOut), "\n")
		if len(lines) >= 2 {
			osName := strings.TrimSpace(lines[1])
			if osName != "" {
				results = append(results, []string{"OS Details", "OS Name", osName})
			}
		}

		osVersionOut, _ := exec.Command("cmd", "/c", "wmic", "os", "get", "Version").Output()
		lines = strings.Split(string(osVersionOut), "\n")
		if len(lines) >= 2 {
			osVersion := strings.TrimSpace(lines[1])
			if osVersion != "" {
				results = append(results, []string{"OS Details", "OS Version", osVersion})
			}
		}

		osBuildOut, _ := exec.Command("cmd", "/c", "wmic", "os", "get", "BuildNumber").Output()
		lines = strings.Split(string(osBuildOut), "\n")
		if len(lines) >= 2 {
			osBuild := strings.TrimSpace(lines[1])
			if osBuild != "" {
				results = append(results, []string{"OS Details", "Build Number", osBuild})
			}
		}

		osArchOut, _ := exec.Command("cmd", "/c", "wmic", "os", "get", "OSArchitecture").Output()
		lines = strings.Split(string(osArchOut), "\n")
		if len(lines) >= 2 {
			osArch := strings.TrimSpace(lines[1])
			if osArch != "" {
				results = append(results, []string{"OS Details", "Architecture", osArch})
			}
		}

		lastBootOut, _ := exec.Command("cmd", "/c", "wmic", "os", "get", "LastBootUpTime").Output()
		lines = strings.Split(string(lastBootOut), "\n")
		if len(lines) >= 2 {
			bootTime := strings.TrimSpace(lines[1])
			if bootTime != "" && len(bootTime) >= 14 {
				year := bootTime[0:4]
				month := bootTime[4:6]
				day := bootTime[6:8]
				hour := bootTime[8:10]
				minute := bootTime[10:12]
				results = append(results, []string{"OS Details", "Last Boot", fmt.Sprintf("%s-%s-%s %s:%s", year, month, day, hour, minute)})
			}
		}

		userOut, _ := exec.Command("cmd", "/c", "net", "user").Output()
		userLines := strings.Split(string(userOut), "\n")
		var users []string
		for _, line := range userLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "User accounts") && !strings.Contains(line, "---") && !strings.Contains(line, "The command completed") {
				parts := strings.Fields(line)
				for _, p := range parts {
					if len(p) > 0 && !strings.Contains(p, "---") {
						users = append(users, p)
					}
				}
			}
		}
		if len(users) > 0 {
			results = append(results, []string{"Users", "Total Users", strconv.Itoa(len(users))})
			results = append(results, []string{"Users", "User List", strings.Join(users, ", ")})
		}

		currentUser, _ := exec.Command("cmd", "/c", "whoami").Output()
		results = append(results, []string{"Users", "Current User", strings.TrimSpace(string(currentUser))})

		isAdmin := "No"
		adminCheck, _ := exec.Command("cmd", "/c", "net", "session").Output()
		if len(adminCheck) > 0 {
			isAdmin = "Yes"
		}
		results = append(results, []string{"Users", "Admin Privileges", isAdmin})

		manufacturerOut, _ := exec.Command("wmic", "computersystem", "get", "manufacturer").Output()
		lines = strings.Split(string(manufacturerOut), "\n")
		if len(lines) >= 2 && strings.TrimSpace(lines[1]) != "" {
			results = append(results, []string{"Hardware", "Manufacturer", strings.TrimSpace(lines[1])})
		}

		modelOut, _ := exec.Command("wmic", "computersystem", "get", "model").Output()
		lines = strings.Split(string(modelOut), "\n")
		if len(lines) >= 2 && strings.TrimSpace(lines[1]) != "" {
			results = append(results, []string{"Hardware", "Model", strings.TrimSpace(lines[1])})
		}

		cpuOut, _ := exec.Command("wmic", "cpu", "get", "Name,MaxClockSpeed,NumberOfCores,NumberOfLogicalProcessors").Output()
		lines = strings.Split(string(cpuOut), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				cpuName := strings.Join(fields[:len(fields)-3], " ")
				results = append(results, []string{"Hardware", "CPU", cpuName})
				results = append(results, []string{"Hardware", "CPU Speed", fields[len(fields)-3] + " MHz"})
				results = append(results, []string{"Hardware", "Physical Cores", fields[len(fields)-2]})
				results = append(results, []string{"Hardware", "Logical Cores", fields[len(fields)-1]})
			}
		}

		memOut, _ := exec.Command("wmic", "memorychip", "get", "Capacity,Speed,Manufacturer,PartNumber").Output()
		lines = strings.Split(string(memOut), "\n")
		var totalMem int64
		ramCount := 0
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line != "" {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					capacity, _ := strconv.ParseInt(fields[0], 10, 64)
					totalMem += capacity
					ramCount++
					results = append(results, []string{"RAM", fmt.Sprintf("Module %d Manufacturer", ramCount), fields[2]})
					results = append(results, []string{"RAM", fmt.Sprintf("Module %d Part Number", ramCount), fields[3]})
					results = append(results, []string{"RAM", fmt.Sprintf("Module %d Speed", ramCount), fields[1] + " MHz"})
				}
			}
		}
		if totalMem > 0 {
			results = append(results, []string{"RAM", "Total Capacity", fmt.Sprintf("%.2f GB", float64(totalMem)/1024/1024/1024)})
		}

		diskOut, _ := exec.Command("wmic", "logicaldisk", "where", "DriveType=3", "get", "DeviceID,Size,FreeSpace,FileSystem,VolumeName").Output()
		lines = strings.Split(string(diskOut), "\n")
		for _, line := range lines[1:] {
			if strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				drive := fields[0]
				fs := fields[1]
				volName := fields[2]
				if volName == "" {
					volName = "Local Disk"
				}
				size, _ := strconv.ParseInt(fields[3], 10, 64)
				free, _ := strconv.ParseInt(fields[4], 10, 64)
				if size > 0 {
					usedGB := float64(size-free) / 1024 / 1024 / 1024
					totalGB := float64(size) / 1024 / 1024 / 1024
					percent := float64(size-free) / float64(size) * 100
					results = append(results, []string{"Storage", drive, fmt.Sprintf("%s (%.1f%%) - %s", volName, percent, fs)})
					results = append(results, []string{"Storage", drive + " Usage", fmt.Sprintf("%.2f GB / %.2f GB", usedGB, totalGB)})
				}
			}
		}

		ipOut, _ := exec.Command("cmd", "/c", "ipconfig", "|", "findstr", "IPv4").Output()
		lines = strings.Split(string(ipOut), "\n")
		var ips []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					ip := strings.TrimSpace(parts[1])
					if ip != "" && !strings.Contains(ip, "127.0.0.1") {
						ips = append(ips, ip)
					}
				}
			}
		}
		if len(ips) > 0 {
			results = append(results, []string{"Network", "IPv4", strings.Join(ips, ", ")})
		}

	} else if runtime.GOOS == "linux" {
		hostname, _ := exec.Command("hostname").Output()
		results = append(results, []string{"System", "Hostname", strings.TrimSpace(string(hostname))})

		osRelease, _ := exec.Command("cat", "/etc/os-release").Output()
		lines := strings.Split(string(osRelease), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					results = append(results, []string{"OS Details", "Distribution", strings.Trim(parts[1], "\"")})
				}
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					results = append(results, []string{"OS Details", "Version", strings.Trim(parts[1], "\"")})
				}
			}
		}

		kernelOut, _ := exec.Command("uname", "-r").Output()
		results = append(results, []string{"OS Details", "Kernel", strings.TrimSpace(string(kernelOut))})

		usersOut, _ := exec.Command("cat", "/etc/passwd").Output()
		userLines := strings.Split(string(usersOut), "\n")
		var users []string
		for _, line := range userLines {
			if strings.Contains(line, "/home/") || strings.Contains(line, "/bin/bash") {
				parts := strings.Split(line, ":")
				if len(parts) > 0 {
					users = append(users, parts[0])
				}
			}
		}
		if len(users) > 0 {
			results = append(results, []string{"Users", "Total Users", strconv.Itoa(len(users))})
			results = append(results, []string{"Users", "User List", strings.Join(users, ", ")})
		}

		currentUser, _ := exec.Command("whoami").Output()
		results = append(results, []string{"Users", "Current User", strings.TrimSpace(string(currentUser))})

		isAdmin := "No"
		if os.Geteuid() == 0 {
			isAdmin = "Yes"
		}
		results = append(results, []string{"Users", "Root Privileges", isAdmin})

		cpuInfo, _ := exec.Command("lscpu").Output()
		lines = strings.Split(string(cpuInfo), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Model name:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					results = append(results, []string{"Hardware", "CPU", strings.TrimSpace(parts[1])})
				}
			}
			if strings.Contains(line, "CPU MHz:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					results = append(results, []string{"Hardware", "CPU Speed", strings.TrimSpace(parts[1]) + " MHz"})
				}
			}
			if strings.Contains(line, "CPU(s):") && !strings.Contains(line, "scaling") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					results = append(results, []string{"Hardware", "CPU Cores", strings.TrimSpace(parts[1])})
				}
			}
		}

		memInfo, _ := exec.Command("free", "-h").Output()
		lines = strings.Split(string(memInfo), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Mem:") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					results = append(results, []string{"RAM", "Total", fields[1]})
					results = append(results, []string{"RAM", "Used", fields[2]})
					results = append(results, []string{"RAM", "Free", fields[3]})
				}
			}
		}

		diskInfo, _ := exec.Command("df", "-h", "--total").Output()
		lines = strings.Split(string(diskInfo), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "total") {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					results = append(results, []string{"Storage", "Total", fields[1]})
					results = append(results, []string{"Storage", "Used", fields[2]})
					results = append(results, []string{"Storage", "Available", fields[3]})
					results = append(results, []string{"Storage", "Usage", fields[4]})
				}
			}
		}

		ipOut, _ := exec.Command("hostname", "-I").Output()
		ips := strings.Fields(string(ipOut))
		if len(ips) > 0 {
			results = append(results, []string{"Network", "IP Addresses", strings.Join(ips, ", ")})
		}
	}

	return results
}