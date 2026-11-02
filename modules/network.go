package modules

import (
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func GetNetworkInfo() [][]string {
	var results [][]string

	if runtime.GOOS == "windows" {
		netstatOut, _ := exec.Command("cmd", "/c", "netstat", "-ano").Output()
		lines := strings.Split(string(netstatOut), "\n")

		var listening, established, udp []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Proto") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				proto := fields[0]
				local := fields[1]
				foreign := fields[2]
				state := ""
				if len(fields) >= 5 {
					state = fields[3]
				}

				if proto == "TCP" {
					if strings.Contains(state, "LISTENING") {
						listening = append(listening, local)
					} else if strings.Contains(state, "ESTABLISHED") {
						established = append(established, local+" -> "+foreign)
					}
				} else if proto == "UDP" {
					udp = append(udp, local)
				}
			}
		}

		results = append(results, []string{"Network", "Listening Ports", strconv.Itoa(len(listening))})
		if len(listening) > 0 {
			results = append(results, []string{"Network", "Listening Details", strings.Join(listening[:10], ", ")})
		}

		results = append(results, []string{"Network", "Established Connections", strconv.Itoa(len(established))})
		if len(established) > 0 {
			results = append(results, []string{"Network", "Active Connections", strings.Join(established[:5], " | ")})
		}

		results = append(results, []string{"Network", "UDP Listeners", strconv.Itoa(len(udp))})

		firewallOut, _ := exec.Command("cmd", "/c", "netsh", "advfirewall", "show", "allprofiles").Output()
		firewallLines := strings.Split(string(firewallOut), "\n")
		for _, line := range firewallLines {
			if strings.Contains(line, "State") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					profile := strings.TrimSpace(parts[0])
					state := strings.TrimSpace(parts[1])
					if strings.Contains(profile, "Profile") {
						results = append(results, []string{"Firewall", profile, state})
					}
				}
			}
		}

	} else if runtime.GOOS == "linux" {
		ssOut, _ := exec.Command("ss", "-tuln").Output()
		lines := strings.Split(string(ssOut), "\n")

		var listening []string
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				local := fields[4]
				if strings.Contains(local, ":") {
					listening = append(listening, local)
				}
			}
		}

		results = append(results, []string{"Network", "Listening Ports", strconv.Itoa(len(listening))})
		if len(listening) > 0 {
			results = append(results, []string{"Network", "Listen Details", strings.Join(listening[:10], ", ")})
		}

		iptablesOut, _ := exec.Command("sudo", "iptables", "-L").Output()
		if len(iptablesOut) > 0 {
			results = append(results, []string{"Firewall", "IPtables", "Active"})
		} else {
			results = append(results, []string{"Firewall", "IPtables", "Inactive or no permission"})
		}
	}

	interfaces, _ := net.Interfaces()
	var interfaceNames []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 {
			interfaceNames = append(interfaceNames, iface.Name)
		}
	}
	results = append(results, []string{"Network", "Active Interfaces", strings.Join(interfaceNames, ", ")})

	return results
}
