package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Batman-Priv/SysPeek/modules"
	"github.com/Batman-Priv/SysPeek/utils"
)

func main() {
	edrFlag := flag.Bool("edr", false, "Run EDR/AV detection module")
	registryFlag := flag.Bool("registry", false, "Run suspicious registry file check module")
	hardwareFlag := flag.Bool("hardware", false, "Run hardware and OS info module")
	servicesFlag := flag.Bool("services", false, "Run services and scheduled tasks module")
	networkFlag := flag.Bool("network", false, "Run network connections module")
	antivirusFlag := flag.Bool("antivirus", false, "Run antivirus and security module")
	filesystemFlag := flag.Bool("filesystem", false, "Run filesystem analysis module")
	environmentFlag := flag.Bool("environment", false, "Run environment variables module")
	logsFlag := flag.Bool("logs", false, "Run logs and history module")
	
	processesLevel := flag.Int("processes", 0, "Processes analysis level: 0=all, 1=only suspicious DLLs")

	lolbinFlag := flag.Bool("lolbin", false, "Scan for LOLBin abuse (mshta/rundll32/regsvr32/certutil/PowerShell/etc) with parent-chain")
	baselineFlag := flag.Bool("baseline", false, "Capture a baseline snapshot of services/tasks/run-keys/drivers")
	diffFlag := flag.Bool("diff", false, "Compare current system state against the last saved baseline")
	correlateFlag := flag.Bool("correlate", false, "Print the aggregated Threat Score / MITRE / Timeline summary")
	persistenceFlag := flag.Bool("persistence", false, "Hunt registry-based persistence (IFEO, AppInit_DLLs, Winlogon, LSA, WMI subscriptions)")
	driversFlag := flag.Bool("drivers", false, "Scan kernel drivers for test-signing mode, missing/invalid signatures, and non-standard paths")
	ransomwareFlag := flag.Bool("ransomware-hunt", false, "Hunt for shadow-copy deletion, backup sabotage, and anti-forensics commands")
	netwatchFlag := flag.Bool("netwatch", false, "Attribute TCP connections to owning processes and flag unsigned/tampered ones")
	lsassFlag := flag.Bool("lsass", false, "Hunt for LSASS credential-dumping command-line/filename signatures")
	autorunsFlag := flag.Bool("autoruns", false, "Unified inventory: services, tasks, run keys, and startup folders in one signature-checked table")
	configInitFlag := flag.Bool("config-init", false, "Write a default syspeek_config.json next to the executable and exit")
	exportFormat := flag.String("export", "", "Export all findings from this run: json, csv, or html")
	exportOutput := flag.String("output", "", "Output file path for --export (default: syspeek_report.<ext>)")

	monitorFlag := flag.Bool("monitor", false, "Continuously poll processes/services/connections and print new activity (Ctrl+C to stop)")
	monitorInterval := flag.Duration("monitor-interval", 3*time.Second, "Polling interval for --monitor (e.g. 2s, 500ms)")
	watchFolderPath := flag.String("watch-folder", "", "Real-time (ReadDirectoryChangesW) watch of a folder for file create/modify/delete/rename")
	watchRecursive := flag.Bool("watch-recursive", false, "Watch subdirectories too (used with --watch-folder)")

	allFlag := flag.Bool("all", false, "Run all modules")
	helpFlag := flag.Bool("help", false, "Show help")

	flag.Parse()

	if *configInitFlag {
		path, err := modules.WriteDefaultConfig("")
		if err != nil {
			fmt.Println("[!] Failed to write config:", err)
			return
		}
		fmt.Println("[+] Default config written to:", path)
		fmt.Println("    Edit it to add trusted publishers, hijack targets, LSASS allowlist entries, or score thresholds.")
		return
	}

	if *monitorFlag {
		modules.RunMonitor(*monitorInterval)
		return
	}

	if *watchFolderPath != "" {
		if err := modules.WatchFolder(*watchFolderPath, *watchRecursive); err != nil {
			fmt.Println("[!] Watch failed:", err)
		}
		return
	}

	if *helpFlag || (!*edrFlag && !*registryFlag && !*hardwareFlag && !*servicesFlag && !*networkFlag && !*antivirusFlag && !*filesystemFlag && !*environmentFlag && !*logsFlag && !*allFlag && !*lolbinFlag && !*baselineFlag && !*diffFlag && !*correlateFlag && !*persistenceFlag && !*driversFlag && !*ransomwareFlag && !*netwatchFlag && !*lsassFlag && !*autorunsFlag && *exportFormat == "" && *processesLevel == 0) {
		printBanner()
		printUsage()
		return
	}

	if *allFlag {
		*edrFlag = true
		*registryFlag = true
		*hardwareFlag = true
		*servicesFlag = true
		*networkFlag = true
		*antivirusFlag = true
		*filesystemFlag = true
		*environmentFlag = true
		*logsFlag = true
		*lolbinFlag = true
		*persistenceFlag = true
		*driversFlag = true
		*ransomwareFlag = true
		*netwatchFlag = true
		*lsassFlag = true
		*autorunsFlag = true
		*correlateFlag = true
		if *processesLevel == 0 {
			*processesLevel = 1
		}
	}

	if *edrFlag {
		fmt.Println("\n[+] Running EDR/AV Detection Module...")
		results := modules.DetectEDR()
		utils.RenderTable("EDR/AV Detection Results", []string{"Security Product", "Status", "Details"}, results)
	}

	if *registryFlag {
		fmt.Println("\n[+] Running Registry Suspicious File Check Module...")
		results := modules.CheckRegistryFiles()
		utils.RenderTable("Suspicious Registry Files", []string{"Registry Path", "File Path", "Verified [Risk]", "Issues"}, results)
	}

	if *hardwareFlag {
		fmt.Println("\n[+] Running Hardware & OS Information Module...")
		results := modules.GetHardwareInfo()
		utils.RenderTable("Hardware & OS Information", []string{"Category", "Property", "Value"}, results)
	}

	if *servicesFlag {
		fmt.Println("\n[+] Running Services & Scheduled Tasks Module...")
		results := modules.GetServices()
		utils.RenderTable("Services & Tasks", []string{"Category", "Property", "Value"}, results)
	}

	if *networkFlag {
		fmt.Println("\n[+] Running Network Analysis Module...")
		results := modules.GetNetworkInfo()
		utils.RenderTable("Network Information", []string{"Category", "Property", "Value"}, results)
	}

	if *antivirusFlag {
		fmt.Println("\n[+] Running Antivirus & Security Module...")
		results := modules.GetAntivirusInfo()
		utils.RenderTable("Security Information", []string{"Category", "Property", "Value"}, results)
	}

	if *filesystemFlag {
		fmt.Println("\n[+] Running Filesystem Analysis Module...")
		results := modules.GetFileSystemInfo()
		utils.RenderTable("Filesystem Information", []string{"Category", "File", "Status/Permission"}, results)
	}

	if *environmentFlag {
		fmt.Println("\n[+] Running Environment Variables Module...")
		results := modules.GetEnvironmentInfo()
		utils.RenderTable("Environment Variables", []string{"Category", "Property", "Value"}, results)
	}

	if *logsFlag {
		fmt.Println("\n[+] Running Logs & History Module...")
		results := modules.GetLogsInfo()
		utils.RenderTable("System Logs & History", []string{"Category", "Property", "Value"}, results)
	}

	if *processesLevel > 0 {
		fmt.Println("\n[+] Running Processes & DLL Analysis Module...")
		results := modules.GetProcessesInfo(*processesLevel)
		utils.RenderTable("Processes & DLL Information", []string{"Process", "DLL Status", "Details"}, results)
	} else if flag.Args() != nil && len(flag.Args()) > 0 {
		
		if flag.Arg(0) == "1" {
			fmt.Println("\n[+] Running Processes & DLL Analysis Module...")
			results := modules.GetProcessesInfo(1)
			utils.RenderTable("Processes & DLL Information", []string{"Process", "DLL Status", "Details"}, results)
		}
	}

	if *lolbinFlag {
		fmt.Println("\n[+] Running LOLBin & Parent-Chain Analyzer...")
		results := modules.GetLOLBinFindings()
		utils.RenderTable("LOLBin Activity", []string{"Process Chain", "Technique", "Command Line"}, results)
	}

	if *baselineFlag {
		fmt.Println("\n[+] Capturing Baseline Snapshot...")
		path, err := modules.CaptureBaseline()
		if err != nil {
			fmt.Println("  Failed to capture baseline:", err)
		} else {
			fmt.Println("  Baseline saved to:", path)
		}
	}

	if *diffFlag {
		fmt.Println("\n[+] Comparing Against Baseline...")
		results := modules.DiffBaseline()
		utils.RenderTable("Baseline Diff", []string{"Category", "Change", "Item"}, results)
	}

	if *persistenceFlag {
		fmt.Println("\n[+] Running Persistence Hunter (IFEO/AppInit/Winlogon/LSA/WMI)...")
		results := modules.GetPersistenceFindings()
		utils.RenderTable("Persistence Findings", []string{"Mechanism", "Key", "Value"}, results)
	}

	if *driversFlag {
		fmt.Println("\n[+] Running Driver Scanner...")
		results := modules.GetDriverFindings()
		utils.RenderTable("Driver Findings", []string{"Driver", "Status", "Path"}, results)
	}

	if *ransomwareFlag {
		fmt.Println("\n[+] Running Ransomware Precursor Hunter...")
		results := modules.GetRansomwareHunterFindings()
		utils.RenderTable("Ransomware Hunt", []string{"Process Chain", "Indicator", "Command Line"}, results)
	}

	if *netwatchFlag {
		fmt.Println("\n[+] Running Network Watch (process-attributed connections)...")
		results := modules.GetNetworkWatchFindings()
		utils.RenderTable("Network Watch", []string{"Process", "State", "Connection"}, results)
	}

	if *lsassFlag {
		fmt.Println("\n[+] Running LSASS Credential-Access Hunter...")
		results := modules.GetLSASSFindings()
		utils.RenderTable("LSASS Findings", []string{"Process Chain", "Indicator", "Command Line"}, results)
	}

	if *autorunsFlag {
		fmt.Println("\n[+] Building Unified Autoruns Inventory...")
		results := modules.GetAutorunsInventory()
		utils.RenderTable("Autoruns Inventory", []string{"Category", "Name", "Signature", "Command"}, results)
	}

	if *correlateFlag {
		modules.RenderCorrelationReport()
	}

	if *exportFormat != "" {
		path, err := modules.ExportReport(*exportFormat, *exportOutput)
		if err != nil {
			fmt.Println("\n[!] Export failed:", err)
		} else {
			fmt.Println("\n[+] Report exported to:", path)
		}
	}
}

func printBanner() {
	fmt.Println(`
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗██╗   ██╗███████╗██████╗ ███████╗███████╗██╗  ██╗                ║
║   ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝██║ ██╔╝                ║
║   ███████╗ ╚████╔╝ ███████╗██████╔╝█████╗  █████╗  █████╔╝                 ║
║   ╚════██║  ╚██╔╝  ╚════██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔═██╗                ║
║   ███████║   ██║   ███████║██║     ███████╗███████╗██║  ██╗                ║
║   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝                ║
║                                                                              ║
║   Advanced System Reconnaissance Tool v2.0                                  ║
║   Multi-Platform (Windows/Linux) - Go Powered                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
`)
}

func printUsage() {
	fmt.Println("USAGE:")
	fmt.Println("  SysPeek.exe [OPTIONS]")
	fmt.Println()
	fmt.Println("OPTIONS:")
	fmt.Println("  --edr               Detect EDR/AV products")
	fmt.Println("  --registry          Check suspicious registry entries")
	fmt.Println("  --hardware          Display hardware and OS info")
	fmt.Println("  --services          Show services and scheduled tasks")
	fmt.Println("  --network           Show network connections and ports")
	fmt.Println("  --antivirus         Check antivirus and security status")
	fmt.Println("  --filesystem        Analyze sensitive files and recent changes")
	fmt.Println("  --environment       Show environment variables")
	fmt.Println("  --logs              Show system logs and command history")
	fmt.Println("  --processes=1       Show processes with suspicious DLLs only")
	fmt.Println("  --processes=0       Show all processes with DLL info")
	fmt.Println("  --lolbin            Scan for LOLBin abuse with parent-chain reconstruction")
	fmt.Println("  --baseline          Capture a baseline snapshot (services/tasks/run-keys/drivers)")
	fmt.Println("  --diff              Compare current state against the last saved baseline")
	fmt.Println("  --persistence       Hunt IFEO/AppInit_DLLs/Winlogon/LSA/WMI persistence")
	fmt.Println("  --drivers           Scan kernel drivers (test-signing, unsigned, non-standard path)")
	fmt.Println("  --ransomware-hunt   Hunt shadow-copy deletion / backup sabotage / anti-forensics")
	fmt.Println("  --netwatch          Attribute network connections to signed/unsigned processes")
	fmt.Println("  --lsass             Hunt LSASS credential-dumping command-line/filename signatures")
	fmt.Println("  --autoruns          Unified inventory of everything that starts automatically")
	fmt.Println("  --config-init       Write a default syspeek_config.json next to the exe and exit")
	fmt.Println("  --monitor           Continuously poll processes/services/connections (Ctrl+C to stop)")
	fmt.Println("  --monitor-interval  Polling interval for --monitor (default 3s)")
	fmt.Println("  --watch-folder=DIR  Real-time folder watch via ReadDirectoryChangesW (Ctrl+C to stop)")
	fmt.Println("  --watch-recursive   Watch subdirectories too (used with --watch-folder)")
	fmt.Println("  --correlate         Print aggregated Threat Score / MITRE / Timeline summary")
	fmt.Println("  --export=FORMAT     Export all findings: json, csv, or html")
	fmt.Println("  --output=PATH       Output path for --export")
	fmt.Println("  --all               Run all modules")
	fmt.Println("  --help              Show this help message")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  SysPeek.exe --all")
	fmt.Println("  SysPeek.exe --processes=1")
	fmt.Println("  SysPeek.exe --edr --antivirus --processes=1")
	fmt.Println("  SysPeek.exe --all --export=html --output=report.html")
	fmt.Println("  SysPeek.exe --baseline    (day 1, then later:)")
	fmt.Println("  SysPeek.exe --diff --persistence --drivers --correlate")
	fmt.Println("  SysPeek.exe --monitor --monitor-interval=2s")
	fmt.Println("  SysPeek.exe --watch-folder=\"C:\\Users\\Public\\Downloads\" --watch-recursive")
	fmt.Println()
	fmt.Println("SUPPORTED PLATFORMS:")
	fmt.Println("  - Windows 7/8/10/11")
	fmt.Println("  - Linux (Ubuntu, Debian, CentOS, etc.)")
	fmt.Println()
	fmt.Println("REQUIREMENTS:")
	fmt.Println("  - Go 1.25+")
	fmt.Println("  - Administrator/root privileges for full features")
	fmt.Println()
	
	if runtime.GOOS == "windows" {
		checkAdmin()
	}
}

func checkAdmin() {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	if err != nil {
		fmt.Println("WARNING: Running without administrator privileges")
		fmt.Println("  Some features may not work properly")
		fmt.Println("  Please run as Administrator for full functionality")
	} else {
		fmt.Println("Running with administrator privileges")
	}
	os.Exit(0)
}
