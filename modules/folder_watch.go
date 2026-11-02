package modules

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fileListDirectory        = 0x0001
	fileShareReadWriteDelete = 0x00000001 | 0x00000002 | 0x00000004
	openExisting             = 3
	fileFlagBackupSemantics  = 0x02000000

	fileNotifyChangeFileName  = 0x00000001
	fileNotifyChangeDirName   = 0x00000002
	fileNotifyChangeAttribs   = 0x00000004
	fileNotifyChangeSize      = 0x00000008
	fileNotifyChangeLastWrite = 0x00000010

	fileActionAdded          = 1
	fileActionRemoved        = 2
	fileActionModified       = 3
	fileActionRenamedOldName = 4
	fileActionRenamedNewName = 5
)

var procReadDirectoryChangesW = modkernel32.NewProc("ReadDirectoryChangesW")

type fileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
}

func actionName(a uint32) string {
	switch a {
	case fileActionAdded:
		return "CREATED"
	case fileActionRemoved:
		return "DELETED"
	case fileActionModified:
		return "MODIFIED"
	case fileActionRenamedOldName:
		return "RENAMED-FROM"
	case fileActionRenamedNewName:
		return "RENAMED-TO"
	default:
		return "UNKNOWN"
	}
}

func looksExecutable(name string) bool {
	lower := strings.ToLower(name)
	exts := []string{".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".hta", ".scr", ".cmd"}
	for _, e := range exts {
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}

func WatchFolder(dir string, recursive bool) error {
	pDir, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}

	handle, err := windows.CreateFile(
		pDir,
		fileListDirectory,
		fileShareReadWriteDelete,
		nil,
		openExisting,
		fileFlagBackupSemantics,
		0,
	)
	if err != nil {
		return fmt.Errorf("could not open %q for watching: %w", dir, err)
	}
	defer windows.CloseHandle(handle)

	fmt.Printf("Watching %s (recursive=%v) for file changes. Press Ctrl+C to stop.\n\n", dir, recursive)

	watchMask := uint32(fileNotifyChangeFileName | fileNotifyChangeDirName |
		fileNotifyChangeLastWrite | fileNotifyChangeSize | fileNotifyChangeAttribs)

	watchSubtree := uintptr(0)
	if recursive {
		watchSubtree = 1
	}

	buf := make([]byte, 64*1024)

	for {
		var bytesReturned uint32
		ret, _, callErr := procReadDirectoryChangesW.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			watchSubtree,
			uintptr(watchMask),
			uintptr(unsafe.Pointer(&bytesReturned)),
			0,
			0,
		)
		if ret == 0 {
			return fmt.Errorf("ReadDirectoryChangesW failed: %v", callErr)
		}
		if bytesReturned == 0 {
			continue
		}

		offset := uint32(0)
		for offset < bytesReturned {
			entry := (*fileNotifyInformation)(unsafe.Pointer(&buf[offset]))

			nameStart := offset + 12 
			nameLen := entry.FileNameLength / 2
			if nameStart+entry.FileNameLength > uint32(len(buf)) || nameLen == 0 {
				break
			}

			nameSlice := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[nameStart])), nameLen)
			name := syscall.UTF16ToString(nameSlice)
			full := strings.TrimRight(dir, `\`) + `\` + name
			action := actionName(entry.Action)

			fmt.Printf("[%s] [%-12s] %s\n", time.Now().Format("15:04:05"), action, full)

			if entry.Action == fileActionAdded && looksExecutable(name) {
				RegisterFinding("watch-folder", full,
					"New executable/script created in watched folder: "+full, 30, "T1105")
			}

			if entry.NextEntryOffset == 0 {
				break
			}
			offset += entry.NextEntryOffset
		}
	}
}
