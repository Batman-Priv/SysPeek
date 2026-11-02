package modules

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")
	modwintrust = windows.NewLazySystemDLL("wintrust.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")

	procCreateToolhelp32Snapshot  = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First            = modkernel32.NewProc("Process32FirstW")
	procProcess32Next             = modkernel32.NewProc("Process32NextW")
	procThread32First             = modkernel32.NewProc("Thread32First")
	procThread32Next              = modkernel32.NewProc("Thread32Next")
	procCloseHandle               = modkernel32.NewProc("CloseHandle")
	procVirtualQueryEx            = modkernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory         = modkernel32.NewProc("ReadProcessMemory")
	procOpenThread                = modkernel32.NewProc("OpenThread")
	procQueryFullProcessImageName = modkernel32.NewProc("QueryFullProcessImageNameW")
	procEnumProcessModulesEx      = modpsapi.NewProc("EnumProcessModulesEx")
	procGetModuleFileNameEx       = modpsapi.NewProc("GetModuleFileNameExW")
	procGetModuleInformation      = modpsapi.NewProc("GetModuleInformation")
	procWinVerifyTrust            = modwintrust.NewProc("WinVerifyTrust")
	procNtQueryInformationThread  = modntdll.NewProc("NtQueryInformationThread")
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
	TH32CS_SNAPTHREAD  = 0x00000004

	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	PROCESS_VM_OPERATION      = 0x0008
	THREAD_QUERY_INFORMATION  = 0x0040

	MAX_PATH = 260

	MEM_PRIVATE = 0x20000
	MEM_IMAGE   = 0x1000000
	MEM_COMMIT  = 0x1000

	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80

	LIST_MODULES_ALL = 0x03

	ThreadQuerySetWin32StartAddress = 9

	TRUST_E_NOSIGNATURE          = 0x800B0100
	TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
	TRUST_E_PROVIDER_UNKNOWN     = 0x800B0001
	TRUST_E_EXPLICIT_DISTRUST    = 0x800B0111
	TRUST_E_SUBJECT_NOT_TRUSTED  = 0x800B0004
	TRUST_E_BAD_DIGEST           = 0x80096010
	CERT_E_EXPIRED               = 0x800B0101
	CERT_E_REVOKED               = 0x800B010C
	CERT_E_UNTRUSTEDROOT         = 0x800B0109
	CERT_E_CHAINING              = 0x800B010A
)

type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

type THREADENTRY32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePriority   int32
	DeltaPriority  int32
	Flags          uint32
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type MODULEINFO struct {
	BaseOfDll  uintptr
	SizeOfDll  uint32
	EntryPoint uintptr
	Path       string
	Name       string
}

type ProcessAnalysis struct {
	PID         uint32
	Name        string
	ParentPID   uint32
	RiskScore   int
	RiskDetails []string
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type WINTRUST_FILE_INFO struct {
	CbStruct       uint32
	PcwszFilePath  uintptr
	HFile          uintptr
	PgKnownSubject uintptr
}

type WINTRUST_DATA struct {
	CbStruct            uint32
	PPolicyCallbackData uintptr
	PSipClientData      uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               uintptr
	DwStateAction       uint32
	HWND                uintptr
	PwszURLReference    uintptr
	DwProvFlags         uint32
	DwUIContext         uint32
	PSignatureSettings  uintptr
}

type sigResult struct {
	Signed    bool
	Signer    string
	Tampered  bool 
	Category  string
	CheckedAt time.Time
}

var (
	sigCache   = map[string]sigResult{}
	sigCacheMu sync.Mutex
)

type statInfo struct {
	size  int64
	mtime int64
}

func statFile(path string) (statInfo, error) {
	var fd windows.Win32finddata
	h, err := windows.FindFirstFile(windows.StringToUTF16Ptr(path), &fd)
	if err != nil {
		return statInfo{}, err
	}
	windows.FindClose(h)
	size := int64(fd.FileSizeHigh)<<32 | int64(fd.FileSizeLow)
	mtime := int64(fd.LastWriteTime.HighDateTime)<<32 | int64(fd.LastWriteTime.LowDateTime)
	return statInfo{size: size, mtime: mtime}, nil
}

func cacheKey(path string) string {
	info, err := statFile(path)
	if err != nil {
		return strings.ToLower(path)
	}
	return fmt.Sprintf("%s|%d|%d", strings.ToLower(path), info.size, info.mtime)
}

func verifySignature(filePath string) sigResult {
	if filePath == "" {
		return sigResult{Signed: false, Category: "no-path"}
	}

	key := cacheKey(filePath)
	sigCacheMu.Lock()
	if cached, ok := sigCache[key]; ok {
		sigCacheMu.Unlock()
		return cached
	}
	sigCacheMu.Unlock()

	result := checkTrust(filePath)
	if result.Signed {
		result.Signer = resolveSigner(filePath)
	}
	result.CheckedAt = time.Now()

	sigCacheMu.Lock()
	sigCache[key] = result
	sigCacheMu.Unlock()

	return result
}

func checkTrust(filePath string) sigResult {
	guid := GUID{
		Data1: 0x00AAC56B,
		Data2: 0xCD44,
		Data3: 0x11D0,
		Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
	}

	fileInfo := WINTRUST_FILE_INFO{
		CbStruct:      uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		PcwszFilePath: uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(filePath))),
	}

	wtd := WINTRUST_DATA{
		CbStruct: uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		
		DwUIChoice: 2,
		
		FdwRevocationChecks: 0,
		DwUnionChoice:       1,
		PFile:               uintptr(unsafe.Pointer(&fileInfo)),
		DwStateAction:       1,
		
		DwProvFlags: 0x00000020,
	}

	ret, _, callErr := procWinVerifyTrust.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&wtd)),
	)

	wtd.DwStateAction = 2
	procWinVerifyTrust.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(&wtd)),
	)

	if ret == 0 {
		return sigResult{Signed: true, Category: "valid"}
	}

	code := int64(int32(ret))
	if code == 0 {
		if errno, ok := callErr.(syscall.Errno); ok {
			code = int64(int32(uint32(errno)))
		}
	}

	switch uint32(code) {
	case TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN:
		return sigResult{Signed: false, Category: "unsigned"}
	case TRUST_E_BAD_DIGEST:
		return sigResult{Signed: false, Tampered: true, Category: "bad-digest"}
	case TRUST_E_EXPLICIT_DISTRUST:
		return sigResult{Signed: false, Tampered: true, Category: "explicitly-distrusted"}
	case CERT_E_REVOKED:
		return sigResult{Signed: false, Tampered: true, Category: "revoked"}
	case CERT_E_EXPIRED:
		return sigResult{Signed: true, Category: "expired"}
	case CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING, TRUST_E_SUBJECT_NOT_TRUSTED:
		return sigResult{Signed: true, Category: "untrusted-chain"}
	default:
		return sigResult{Signed: false, Category: "unsigned"}
	}
}

func resolveSigner(filePath string) string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("(Get-AuthenticodeSignature -LiteralPath '%s').SignerCertificate.Subject",
			strings.ReplaceAll(filePath, "'", "''")))
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	subject := strings.TrimSpace(string(out))
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return subject
}

func isTrustedPublisher(signer string) bool {
	if signer == "" {
		return false
	}
	for _, t := range LoadConfig().TrustedPublishers {
		if strings.Contains(signer, t) {
			return true
		}
	}
	return false
}

func isHijackTarget(lowerName string) bool {
	for _, t := range LoadConfig().HijackTargets {
		if strings.ToLower(t) == lowerName {
			return true
		}
	}
	return false
}

func isCommonAppLocation(lowerPath string) bool {
	markers := []string{
		"\\appdata\\local\\programs\\",
		"\\appdata\\local\\",
		"\\programdata\\",
		"\\scoop\\",
	}
	for _, m := range markers {
		if strings.Contains(lowerPath, m) {
			return true
		}
	}
	return false
}

func GetProcessesInfo(level int) [][]string {
	var results [][]string

	processes := enumProcesses()

	seenModulesByName := map[string][]string{}

	for _, proc := range processes {
		name := syscall.UTF16ToString(proc.ExeFile[:])

		if isSystemProcess(name) {
			continue
		}

		handle, err := windows.OpenProcess(
			PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_OPERATION,
			false,
			proc.ProcessID,
		)
		if err != nil {
			continue
		}

		analysis := analyzeProcess(handle, proc, seenModulesByName)
		windows.CloseHandle(handle)

		if (level == 1 && analysis.RiskScore > 0) || level == 0 {
			th := LoadConfig().Thresholds
			riskLevel := "LOW"
			if analysis.RiskScore >= th.High {
				riskLevel = "CRITICAL"
			} else if analysis.RiskScore >= th.Medium {
				riskLevel = "HIGH"
			} else if analysis.RiskScore >= th.Low {
				riskLevel = "MEDIUM"
			}

			details := fmt.Sprintf("Score: %d", analysis.RiskScore)
			if len(analysis.RiskDetails) > 0 {
				details += " | " + strings.Join(analysis.RiskDetails[:min(3, len(analysis.RiskDetails))], "; ")
			}

			results = append(results, []string{
				fmt.Sprintf("%s (PID:%d, PPID:%d)", name, proc.ProcessID, proc.ParentProcessID),
				fmt.Sprintf("Risk: %s", riskLevel),
				details,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, []string{"No suspicious processes found", "Clean", "All processes appear legitimate"})
	}

	return results
}

func isSystemProcess(name string) bool {
	systemProcesses := map[string]bool{
		"System Idle Process": true,
		"System":              true,
		"Registry":            true,
		"smss.exe":            true,
		"csrss.exe":           true,
		"wininit.exe":         true,
		"services.exe":        true,
		"lsass.exe":           true,
		"winlogon.exe":        true,
	}
	return systemProcesses[name]
}

func enumProcesses() []PROCESSENTRY32 {
	var processes []PROCESSENTRY32

	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == 0 {
		return processes
	}
	defer procCloseHandle.Call(snapshot)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return processes
	}

	for {
		processes = append(processes, entry)
		ret, _, _ := procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return processes
}

func analyzeProcess(handle windows.Handle, proc PROCESSENTRY32, seenModulesByName map[string][]string) ProcessAnalysis {
	analysis := ProcessAnalysis{
		PID:       proc.ProcessID,
		Name:      syscall.UTF16ToString(proc.ExeFile[:]),
		ParentPID: proc.ParentProcessID,
	}

	modules := enumModulesEx(handle)

	memInfo := queryVirtualMemory(handle)


	threads := enumThreads(proc.ProcessID)
	suspiciousThreads := 0
	for _, thread := range threads {
		startAddr := getThreadStartAddress(thread.ThreadID)
		if startAddr == 0 {
			continue
		}

		inModule := false
		for _, mod := range modules {
			if startAddr >= mod.BaseOfDll && startAddr < mod.BaseOfDll+uintptr(mod.SizeOfDll) {
				inModule = true
				break
			}
		}

		if !inModule {
			suspiciousThreads++
		}
	}

	subject := fmt.Sprintf("%s (PID:%d)", analysis.Name, analysis.PID)

	if suspiciousThreads > 0 {
		sev := min(100, suspiciousThreads*40)
		analysis.RiskScore += sev
		detail := fmt.Sprintf("%d threads outside modules", suspiciousThreads)
		analysis.RiskDetails = append(analysis.RiskDetails, detail)
		RegisterFinding("processes", subject, detail, sev, "T1055")
	}

	memScore := 0
	if memInfo.HasPrivateExecutable && memInfo.LargestRegion > 32768 {
		memScore += 15
	}
	if memInfo.HasPrivateRWX && memInfo.LargestRegion > 32768 {
		memScore += 15
	}
	if memInfo.HasReflectivePE {
		memScore += 60
		detail := "PE header found in private RWX memory (possible reflective/manual-mapped module)"
		analysis.RiskDetails = append(analysis.RiskDetails, detail)
		RegisterFinding("processes", subject, detail, 60, "T1055.001")
	}
	analysis.RiskScore += memScore
	if memScore > 0 && !memInfo.HasReflectivePE {
		detail := "Private executable/RWX memory"
		analysis.RiskDetails = append(analysis.RiskDetails, detail)
		if memScore >= 30 {
			RegisterFinding("processes", subject, detail, memScore, "T1055")
		}
	}

	// --- Module / DLL analysis ---
	systemRoot, _ := syscall.Getenv("SystemRoot")
	programFiles, _ := syscall.Getenv("ProgramFiles")
	programFilesX86, _ := syscall.Getenv("ProgramFiles(x86)")

	exePath := getProcessImagePath(handle)
	exeDir := strings.ToLower(filepath.Dir(exePath))

	for _, mod := range modules {
		lowerPath := strings.ToLower(mod.Path)
		lowerName := strings.ToLower(mod.Name)
		modDir := strings.ToLower(filepath.Dir(mod.Path))

		inSystem32 := strings.Contains(lowerPath, strings.ToLower(systemRoot)+"\\system32\\") ||
			strings.Contains(lowerPath, strings.ToLower(systemRoot)+"\\syswow64\\")

		// DLL search-order hijack check runs even for modules we'd otherwise
		// skip below, because the whole point is "this should have been in
		
		if isHijackTarget(lowerName) && !inSystem32 {
			analysis.RiskScore += 70
			detail := fmt.Sprintf("Possible DLL search-order hijack: %s loaded from %s instead of System32", mod.Name, modDir)
			analysis.RiskDetails = append(analysis.RiskDetails, detail)
			RegisterFinding("processes", subject, detail, 70, "T1574.001")
		}

		if inSystem32 {
			continue
		}

		if strings.Contains(lowerPath, strings.ToLower(programFiles)) ||
			strings.Contains(lowerPath, strings.ToLower(programFilesX86)) {
			continue
		}

		sig := verifySignature(mod.Path)

		sameDirAsExe := modDir == exeDir

		locationScore := 0
		locationNote := ""
		switch {
		case strings.Contains(lowerPath, "\\temp\\") || strings.Contains(lowerPath, "\\downloads\\"):
			locationScore = 20
			locationNote = "DLL in temp/downloads"
		case strings.Contains(lowerPath, "\\desktop\\") || strings.Contains(lowerPath, "\\public\\"):
			locationScore = 15
			locationNote = "DLL in desktop/public"
		case strings.Contains(lowerPath, "\\appdata\\roaming\\"):
			locationScore = 8
			locationNote = "DLL in AppData\\Roaming"
		case sameDirAsExe || isCommonAppLocation(lowerPath):
			locationScore = 0 // normal install pattern, no penalty on its own
		case !strings.Contains(lowerPath, "\\windows\\"):
			locationScore = 5
			locationNote = "Non-standard DLL location"
		}

		sigScore := 0
		sigNote := ""
		switch {
		case sig.Tampered:
			sigScore = 90
			sigNote = fmt.Sprintf("TAMPERED signature (%s): %s", sig.Category, mod.Name)
		case !sig.Signed:
			sigScore = 10
			sigNote = "Unsigned DLL: " + mod.Name
		case sig.Category == "untrusted-chain":
			sigScore = 12
			sigNote = "Untrusted certificate chain: " + mod.Name
		case sig.Category == "expired":
			sigScore = 6
			sigNote = "Expired certificate: " + mod.Name
		case !isTrustedPublisher(sig.Signer):
			sigScore = 4
			if sig.Signer != "" {
				sigNote = fmt.Sprintf("Signed by non-allowlisted publisher (%s): %s", sig.Signer, mod.Name)
			} else {
				sigNote = "Signed, publisher could not be resolved: " + mod.Name
			}
		}

		combined := locationScore + sigScore

		if locationScore >= 15 && sigScore >= 10 {
			combined += 20
		}

		if combined > 0 {
			analysis.RiskScore += combined
			note := sigNote
			if locationNote != "" {
				note = locationNote + " + " + sigNote
			}
			if note != "" {
				analysis.RiskDetails = append(analysis.RiskDetails, note)
			}

			if sig.Tampered {
				RegisterFinding("processes", subject, note, combined, "T1036.001", "T1553.002")
			} else if combined >= 30 {
				RegisterFinding("processes", subject, note, combined, "T1027")
			}
		}

		if dirs, ok := seenModulesByName[lowerName]; ok {
			dup := false
			for _, d := range dirs {
				if d == modDir {
					dup = true
					break
				}
			}
			if !dup {
				seenModulesByName[lowerName] = append(seenModulesByName[lowerName], modDir)
				if len(seenModulesByName[lowerName]) > 1 {
					analysis.RiskScore += 10
					analysis.RiskDetails = append(analysis.RiskDetails,
						fmt.Sprintf("%s also seen loaded from a different directory elsewhere on this host", mod.Name))
				}
			}
		} else {
			seenModulesByName[lowerName] = []string{modDir}
		}
	}

	if strings.Contains(strings.ToLower(exePath), " (deleted)") {
		analysis.RiskScore += 80
		detail := "Deleted executable (fileless)"
		analysis.RiskDetails = append(analysis.RiskDetails, detail)
		RegisterFinding("processes", subject, detail, 80, "T1055", "T1027")
	}

	return analysis
}

func enumModulesEx(handle windows.Handle) []MODULEINFO {
	var modules []MODULEINFO

	var cbNeeded uint32
	ret, _, _ := procEnumProcessModulesEx.Call(
		uintptr(handle),
		0,
		0,
		uintptr(unsafe.Pointer(&cbNeeded)),
		LIST_MODULES_ALL,
	)
	if ret == 0 {
		return modules
	}

	count := cbNeeded / uint32(unsafe.Sizeof(windows.Handle(0)))
	hMods := make([]windows.Handle, count)

	ret, _, _ = procEnumProcessModulesEx.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&hMods[0])),
		uintptr(cbNeeded),
		uintptr(unsafe.Pointer(&cbNeeded)),
		LIST_MODULES_ALL,
	)
	if ret == 0 {
		return modules
	}

	for i := 0; i < int(count); i++ {
		var modInfo MODULEINFO
		ret, _, _ := procGetModuleInformation.Call(
			uintptr(handle),
			uintptr(hMods[i]),
			uintptr(unsafe.Pointer(&modInfo)),
			unsafe.Sizeof(modInfo),
		)
		if ret != 0 {
			var fileName [MAX_PATH]uint16
			procGetModuleFileNameEx.Call(
				uintptr(handle),
				uintptr(hMods[i]),
				uintptr(unsafe.Pointer(&fileName[0])),
				MAX_PATH,
			)
			path := syscall.UTF16ToString(fileName[:])
			modInfo.Path = path
			modInfo.Name = path[strings.LastIndex(path, "\\")+1:]
			modules = append(modules, modInfo)
		}
	}

	return modules
}

func enumThreads(pid uint32) []THREADENTRY32 {
	var threads []THREADENTRY32

	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPTHREAD, 0)
	if snapshot == 0 {
		return threads
	}
	defer procCloseHandle.Call(snapshot)

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return threads
	}

	for {
		if entry.OwnerProcessID == pid {
			threads = append(threads, entry)
		}
		ret, _, _ := procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return threads
}

func getThreadStartAddress(tid uint32) uintptr {
	handle, _, _ := procOpenThread.Call(
		THREAD_QUERY_INFORMATION,
		0,
		uintptr(tid),
	)
	if handle == 0 {
		return 0
	}
	defer procCloseHandle.Call(handle)

	var startAddr uintptr
	var returnLength uint32

	ret, _, _ := procNtQueryInformationThread.Call(
		handle,
		ThreadQuerySetWin32StartAddress,
		uintptr(unsafe.Pointer(&startAddr)),
		unsafe.Sizeof(startAddr),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret != 0 {
		return 0
	}

	return startAddr
}

type memScanResult struct {
	HasPrivateExecutable bool
	HasPrivateRWX        bool
	HasReflectivePE      bool
	LargestRegion        uintptr
}

func queryVirtualMemory(handle windows.Handle) memScanResult {
	var result memScanResult

	var mbi MEMORY_BASIC_INFORMATION
	address := uintptr(0)

	for {
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			address,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}

		if mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT {
			isExecutable := (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0
			isRWX := mbi.Protect == PAGE_EXECUTE_READWRITE

			if isExecutable && mbi.RegionSize > result.LargestRegion {
				result.LargestRegion = mbi.RegionSize
				result.HasPrivateExecutable = true
			}
			if isRWX && mbi.RegionSize > result.LargestRegion {
				result.LargestRegion = mbi.RegionSize
				result.HasPrivateRWX = true
			}

			// Peek the first two bytes of any private+executable region for
			// an "MZ" stamp. A legitimately loaded module comes in as
			// MEM_IMAGE, not MEM_PRIVATE — a PE header sitting in private
			// memory is a strong reflective-loading / manual-mapping signal.
			if isExecutable && !result.HasReflectivePE {
				var header [2]byte
				var bytesRead uintptr
				ret, _, _ := procReadProcessMemory.Call(
					uintptr(handle),
					mbi.BaseAddress,
					uintptr(unsafe.Pointer(&header[0])),
					2,
					uintptr(unsafe.Pointer(&bytesRead)),
				)
				if ret != 0 && bytesRead == 2 && header[0] == 'M' && header[1] == 'Z' {
					result.HasReflectivePE = true
				}
			}
		}

		address = mbi.BaseAddress + mbi.RegionSize
	}

	return result
}

func getProcessImagePath(handle windows.Handle) string {
	var buf [MAX_PATH]uint16
	size := uint32(MAX_PATH)

	ret, _, _ := procQueryFullProcessImageName.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return ""
	}

	return syscall.UTF16ToString(buf[:size])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
