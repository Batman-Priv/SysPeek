package modules

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type monitorSnapshot struct {
	Processes map[int]winProcess
	Services  map[string]bool
	Conns     map[string]bool
}

func captureMonitorSnapshot() monitorSnapshot {
	snap := monitorSnapshot{
		Processes: map[int]winProcess{},
		Services:  map[string]bool{},
		Conns:     map[string]bool{},
	}

	if procs, err := fetchProcessListWMI(); err == nil {
		for _, p := range procs {
			snap.Processes[p.ProcessId] = p
		}
	}

	for _, line := range psLines(`Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name)|$($_.State)" }`) {
		snap.Services[line] = true
	}

	for _, line := range psLines(`Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object { "$($_.State)|$($_.LocalPort)|$($_.RemoteAddress)|$($_.RemotePort)|$($_.OwningProcess)" }`) {
		snap.Conns[line] = true
	}

	return snap
}

func printMonitorLine(kind, msg string) {
	fmt.Printf("[%s] [%-9s] %s\n", time.Now().Format("15:04:05"), strings.ToUpper(kind), msg)
}

func diffMonitorSnapshots(prev, curr monitorSnapshot) {
	for pid, p := range curr.Processes {
		if _, ok := prev.Processes[pid]; !ok {
			chain := buildChain(pid, curr.Processes)
			printMonitorLine("process+", fmt.Sprintf("New process: %s (PID:%d) chain=%s", p.Name, pid, chain))
			RegisterFinding("monitor", fmt.Sprintf("%s (PID:%d)", p.Name, pid), "New process observed during live monitoring", 10)
		}
	}
	for pid, p := range prev.Processes {
		if _, ok := curr.Processes[pid]; !ok {
			printMonitorLine("process-", fmt.Sprintf("Process exited: %s (PID:%d)", p.Name, pid))
		}
	}

	for s := range curr.Services {
		if !prev.Services[s] {
			printMonitorLine("service+", "New/changed service state: "+s)
			RegisterFinding("monitor", s, "New/changed service observed during live monitoring", 20, "T1543.003")
		}
	}
	for s := range prev.Services {
		if !curr.Services[s] {
			printMonitorLine("service-", "Service state no longer present: "+s)
		}
	}

	for c := range curr.Conns {
		if !prev.Conns[c] {
			printMonitorLine("conn+", "New network connection: "+c)
		}
	}
	for c := range prev.Conns {
		if !curr.Conns[c] {
			printMonitorLine("conn-", "Connection closed: "+c)
		}
	}
}

func RunMonitor(interval time.Duration) {
	if interval < time.Second {
		interval = time.Second
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("Monitoring processes, services, and network connections every %s. Press Ctrl+C to stop.\n\n", interval)

	prev := captureMonitorSnapshot()
	printMonitorLine("baseline", fmt.Sprintf("Initial snapshot: %d processes, %d services, %d connections",
		len(prev.Processes), len(prev.Services), len(prev.Conns)))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nMonitor stopped.")
			return
		case <-ticker.C:
			curr := captureMonitorSnapshot()
			diffMonitorSnapshots(prev, curr)
			prev = curr
		}
	}
}
