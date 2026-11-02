package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func CheckRegistryFiles() [][]string {
	var results [][]string

	if runtime.GOOS != "windows" {
		results = append(results, []string{"N/A", "N/A", "N/A", "Registry check only available on Windows"})
		return results
	}

	registryPaths := []string{
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`,
		`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`,
		`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`,
		`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`,
		`HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`,
		`HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls`,
		`HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages`,
		`HKLM\System\CurrentControlSet\Control\Lsa\Notification Packages`,
		`HKLM\System\CurrentControlSet\Control\Lsa\Security Packages`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\BrowserHelperObjects`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\BrowserHelperObjects`,
		`HKLM\Software\Microsoft\Internet Explorer\Extensions`,
		`HKCU\Software\Microsoft\Internet Explorer\Extensions`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler`,
	}

	systemFiles := map[string]bool{
		"kernel32.dll": true, "kernelbase.dll": true, "ntdll.dll": true,
		"user32.dll": true, "gdi32.dll": true, "win32u.dll": true,
		"advapi32.dll": true, "msvcrt.dll": true, "sechost.dll": true,
		"rpcrt4.dll": true, "ole32.dll": true, "oleaut32.dll": true,
		"combase.dll": true, "shell32.dll": true, "shlwapi.dll": true,
		"ws2_32.dll": true, "crypt32.dll": true, "bcrypt.dll": true,
		"msctf.dll": true, "imm32.dll": true, "wow64.dll": true,
		"wow64cpu.dll": true, "wow64win.dll": true, "xtajit.dll": true,
		"clbcatq.dll": true, "comdlg32.dll": true, "coml2.dll": true,
		"difxapi.dll": true, "gdiplus.dll": true, "imagehlp.dll": true,
		"normaliz.dll": true, "nsi.dll": true, "psapi.dll": true,
		"setupapi.dll": true, "shcore.dll": true, "wldap32.dll": true,
		"wow64base.dll": true, "wow64con.dll": true, "xtajit64.dll": true,
		"xtajitf.dll": true, "xtajitse.dll": true, "xtajit64se.dll": true,
		"explorer.exe": true, "svchost.exe": true, "services.exe": true,
		"lsass.exe": true, "winlogon.exe": true, "csrss.exe": true,
		"smss.exe": true, "wininit.exe": true, "taskhostw.exe": true,
		"dwm.exe": true, "ctfmon.exe": true, "userinit.exe": true,
		"wlanext.exe": true, "sppsvc.exe": true, "spoolsv.exe": true,
		"msmpeng.exe": true, "securityhealthservice.exe": true,
	}

	safeEntries := map[string]bool{
		"WebCheck": true, "SysTray": true, "Bluetooth": true,
		"Adobe ARM": true, "AdobeAAMUpdater": true, "AdobeGCInvoker": true,
		"GoogleUpdate": true, "Google Chrome": true, "GoggleUpdate": true,
		"Dropbox": true, "DropboxUpdate": true, "OneDrive": true,
		"Skype": true, "SkypeUpdate": true, "Spotify": true,
		"Discord": true, "Slack": true, "Zoom": true,
		"ZoomUpdate": true, "Webex": true,
		"Java": true, "JavaUpdate": true, "SunJavaUpdateSched": true,
		"VMware": true, "vmware-tray": true, "VMwareTray": true,
		"VirtualBox": true, "VBoxTray": true, "Docker": true,
		"WSL": true, "Windows Subsystem": true, "WSLService": true,
		"iTunes": true, "Apple": true, "Bonjour": true,
		"Adobe": true, "Acrobat": true, "Reader": true,
		"Office": true, "Microsoft Office": true, "Outlook": true,
		"OneNote": true, "PowerPoint": true,
		"Excel": true, "Word": true, "Publisher": true,
		"Steam": true, "Epic Games": true, "Battle.net": true,
		"Origin": true, "GOG": true, "Ubisoft": true,
		"GeForce": true, "NVIDIA": true, "AMD": true,
		"Intel": true, "Realtek": true, "Audio": true,
		"Sound": true, "Display": true, "Monitor": true,
		"Printer": true, "Scanner": true, "Fax": true,
		"VPN": true, "Cisco": true, "Fortinet": true,
		"Sophos": true, "McAfee": true, "Norton": true,
		"Bitdefender": true, "Kaspersky": true, "Avast": true,
		"AVG": true, "ESET": true, "Malwarebytes": true,
		"CCleaner": true, "Cleaner": true, "Optimizer": true,
		"Driver": true, "Update": true, "Updater": true,
		"Service": true, "Helper": true, "Assistant": true,
		"Defender": true, "Security": true, "Antivirus": true,
		"Firewall": true, "Protection": true, "Guard": true,
		"Shield": true, "Vault": true, "Locker": true,
	}

	for _, regPath := range registryPaths {
		if strings.Contains(regPath, `Services`) && !strings.Contains(regPath, `AppCertDlls`) && !strings.Contains(regPath, `Lsa`) {
			continue
		}

		cmd := exec.Command("reg", "query", regPath)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "HKEY_") || strings.Contains(line, "WARNING:") {
				continue
			}

			var valueName, filePath string
			var rawPath string

			if strings.Contains(line, "REG_SZ") || strings.Contains(line, "REG_EXPAND_SZ") || strings.Contains(line, "REG_MULTI_SZ") {
				regType := "REG_SZ"
				if strings.Contains(line, "REG_EXPAND_SZ") {
					regType = "REG_EXPAND_SZ"
				} else if strings.Contains(line, "REG_MULTI_SZ") {
					regType = "REG_MULTI_SZ"
				}
				
				parts := strings.SplitN(line, regType, 2)
				if len(parts) == 2 {
					before := strings.TrimSpace(parts[0])
					rawPath = strings.TrimSpace(parts[1])
					
					valueParts := strings.Fields(before)
					if len(valueParts) > 0 {
						valueName = strings.Join(valueParts, " ")
					}
					
					if valueName == "ImagePath" || valueName == "ServiceDll" {
						continue
					}
				}
			} else {
				continue
			}

			if rawPath == "" {
				continue
			}

			filePath = strings.Trim(rawPath, "\"")
			filePath = strings.TrimSpace(filePath)

			if strings.Contains(filePath, "svchost.exe") || strings.Contains(filePath, "dllhost.exe") {
				continue
			}

			fileName := filepath.Base(filePath)
			if systemFiles[strings.ToLower(fileName)] {
				continue
			}

			if len(fileName) < 3 {
				continue
			}

			parts := strings.Split(fileName, ".")
			if len(parts) >= 2 {
				ext := strings.ToLower(parts[len(parts)-1])
				if ext == "log" || ext == "txt" || ext == "dat" || ext == "bin" || ext == "tmp" {
					continue
				}
			}

			if safeEntries[valueName] || safeEntries[strings.TrimSpace(valueName)] {
				continue
			}

			verified := "Yes"
			issues := "None"
			fullPath := filePath
			riskScore := 0
			riskLevel := "LOW"

			if strings.Contains(filePath, "%") {
				expanded, err := exec.Command("cmd", "/c", "echo", filePath).Output()
				if err == nil {
					expandedPath := strings.TrimSpace(string(expanded))
					if expandedPath != filePath && expandedPath != "" {
						fullPath = expandedPath
					}
				}
			}

			if _, err := os.Stat(fullPath); os.IsNotExist(err) {
				verified = "No"
				issues = "File does not exist"
				riskScore += 30
				
				found := false
				searchPaths := []string{
					os.Getenv("SystemRoot") + "\\System32\\" + fileName,
					os.Getenv("SystemRoot") + "\\" + fileName,
					os.Getenv("ProgramFiles") + "\\" + fileName,
					os.Getenv("ProgramFiles(x86)") + "\\" + fileName,
					os.Getenv("SystemRoot") + "\\SysWOW64\\" + fileName,
				}
				for _, sp := range searchPaths {
					if _, err := os.Stat(sp); err == nil {
						fullPath = sp
						verified = "Yes"
						issues = "Found in alternate location"
						riskScore += 10
						found = true
						break
					}
				}
				if !found {
					fullPath = filePath + " (missing)"
				}
			} else {
				if absPath, err := filepath.Abs(fullPath); err == nil {
					fullPath = absPath
				}
				
				fileInfo, err := os.Stat(fullPath)
				if err == nil {
					if fileInfo.ModTime().Year() < 2018 {
						riskScore += 10
						if issues == "None" {
							issues = "Old file"
						} else {
							issues += " | Old file"
						}
					}
				}
			}

			lowerPath := strings.ToLower(fullPath)
			if verified == "Yes" {
				if strings.Contains(lowerPath, "\\temp\\") ||
					strings.Contains(lowerPath, "\\downloads\\") ||
					strings.Contains(lowerPath, "\\appdata\\local\\temp\\") ||
					strings.Contains(lowerPath, "\\windows\\temp\\") {
					issues = "CRITICAL: Temp folder"
					riskScore += 40
				} else if strings.Contains(lowerPath, "\\desktop\\") {
					issues = "HIGH: Desktop location"
					riskScore += 35
				} else if strings.Contains(lowerPath, "\\downloads\\") {
					issues = "HIGH: Downloads folder"
					riskScore += 35
				} else if strings.Contains(lowerPath, "\\users\\") && !strings.Contains(lowerPath, "\\appdata\\") {
					if issues == "None" {
						issues = "MEDIUM: User folder"
					} else {
						issues += " | User folder"
					}
					riskScore += 25
				} else if !strings.Contains(lowerPath, "\\windows\\") &&
					!strings.Contains(lowerPath, "\\program files") &&
					!strings.Contains(lowerPath, "\\program files (x86)") &&
					!strings.Contains(lowerPath, "\\system32\\") {
					if issues == "None" {
						issues = "MEDIUM: Non-standard location"
					} else {
						issues += " | Non-standard"
					}
					riskScore += 20
				}

				if strings.HasPrefix(lowerPath, "c:\\windows\\") && !strings.HasPrefix(lowerPath, "c:\\windows\\system32") {
					riskScore += 15
					if issues == "None" {
						issues = "MEDIUM: Windows root"
					}
				}
			}

			if strings.Contains(strings.ToLower(valueName), "bot") ||
			   strings.Contains(strings.ToLower(valueName), "trojan") ||
			   strings.Contains(strings.ToLower(valueName), "worm") ||
			   strings.Contains(strings.ToLower(valueName), "ransom") ||
			   strings.Contains(strings.ToLower(valueName), "crypt") ||
			   strings.Contains(strings.ToLower(valueName), "miner") {
				issues = "CRITICAL: Suspicious name"
				riskScore += 50
			}

			ext := strings.ToLower(filepath.Ext(fileName))
			if ext == ".scr" || ext == ".com" || ext == ".pif" || ext == ".cpl" {
				if issues == "None" {
					issues = "HIGH: Dangerous extension"
				} else {
					issues += " | Dangerous extension"
				}
				riskScore += 30
			} else if ext == ".vbs" || ext == ".js" || ext == ".jse" || ext == ".ps1" {
				if issues == "None" {
					issues = "MEDIUM: Script file"
				} else {
					issues += " | Script"
				}
				riskScore += 20
			}

			if riskScore >= 40 {
				riskLevel = "HIGH"
			} else if riskScore >= 20 {
				riskLevel = "MEDIUM"
			} else {
				riskLevel = "LOW"
			}

			if issues != "None" || riskScore > 0 {
				if valueName != "" && valueName != "(Default)" {
					displayPath := regPath + " -> " + valueName
					results = append(results, []string{
						displayPath,
						fullPath,
						verified + " [" + riskLevel + "]",
						issues,
					})
				} else {
					results = append(results, []string{
						regPath,
						fullPath,
						verified + " [" + riskLevel + "]",
						issues,
					})
				}
			}
		}
	}

	if len(results) == 0 {
		results = append(results, []string{"No suspicious entries found", "N/A", "Clean", "System appears secure"})
	}

	return results
}