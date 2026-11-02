package modules

import (
	"fmt"
	"strconv"
	"strings"
)

type netConn struct {
	LocalAddr  string
	LocalPort  string
	RemoteAddr string
	RemotePort string
	State      string
	PID        int
	ProcName   string
	ProcPath   string
}

func GetNetworkWatchFindings() [][]string {
	var results [][]string

	lines := psLines(`Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "$($_.LocalAddress)|$($_.LocalPort)|$($_.RemoteAddress)|$($_.RemotePort)|$($_.State)|$($_.OwningProcess)|$($p.ProcessName)|$($p.Path)" }`)

	for _, line := range lines {
		parts := strings.SplitN(line, "|", 8)
		if len(parts) != 8 {
			continue
		}
		conn := netConn{
			LocalAddr: parts[0], LocalPort: parts[1],
			RemoteAddr: parts[2], RemotePort: parts[3],
			State: parts[4], ProcName: parts[6], ProcPath: parts[7],
		}
		pid, _ := strconv.Atoi(parts[5])
		conn.PID = pid

		if conn.ProcPath == "" {
			continue
		}

		sig := verifySignature(conn.ProcPath)
		subject := fmt.Sprintf("%s (PID:%d)", conn.ProcName, conn.PID)

		suspicious := false
		note := ""
		sev := 0

		remoteIsPublic := !isPrivateIP(conn.RemoteAddr)

		switch {
		case conn.State == "Established" && remoteIsPublic && sig.Tampered:
			suspicious, sev = true, 90
			note = fmt.Sprintf("Process with TAMPERED signature has an outbound connection to %s:%s", conn.RemoteAddr, conn.RemotePort)
		case conn.State == "Established" && remoteIsPublic && !sig.Signed:
			suspicious, sev = true, 35
			note = fmt.Sprintf("Unsigned process has an outbound connection to %s:%s", conn.RemoteAddr, conn.RemotePort)
		case conn.State == "Listen" && !sig.Signed:
			suspicious, sev = true, 40
			note = fmt.Sprintf("Unsigned process is listening on port %s", conn.LocalPort)
		}

		if suspicious {
			results = append(results, []string{subject, conn.State,
				fmt.Sprintf("%s:%s -> %s:%s | %s", conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort, note)})
			RegisterFinding("netwatch", subject, note, sev, "T1071")
		}
	}

	if len(results) == 0 {
		results = append(results, []string{"No suspicious network activity found", "Clean", "All connections belong to signed processes or private ranges"})
	}

	return results
}

func isPrivateIP(ip string) bool {
	if ip == "" || ip == "0.0.0.0" || ip == "::" || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") {
		return true
	}
	prefixes := []string{"10.", "192.168.", "169.254.", "fe80:"}
	for _, p := range prefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil && n >= 16 && n <= 31 {
				return true
			}
		}
	}
	return false
}
