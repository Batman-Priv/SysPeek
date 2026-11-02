package modules

import (
	"fmt"
	"os"
	"strings"
)

func GetDriverFindings() [][]string {
	var results [][]string

	testSigning := psLines(`(bcdedit /enum) | Select-String 'testsigning\s+Yes'`)
	if len(testSigning) > 0 {
		results = append(results, []string{"Test Signing", "ENABLED", "Driver signature enforcement is relaxed on this host"})
		RegisterFinding("drivers", "bcdedit", "Test Signing Mode is enabled - unsigned/self-signed drivers can load", 60, "T1553.006")
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}

	driverLines := psLines(`Get-CimInstance Win32_SystemDriver | ForEach-Object { "$($_.Name)|$($_.PathName)|$($_.State)" }`)

	for _, line := range driverLines {
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		name, rawPath, state := parts[0], strings.TrimSpace(parts[1]), parts[2]
		if rawPath == "" {
			continue
		}

		path := resolveDriverPath(rawPath, systemRoot)
		lowerPath := strings.ToLower(path)
		inSystem32Drivers := strings.Contains(lowerPath, `\system32\drivers\`)

		sig := verifySignature(path)

		switch {
		case sig.Tampered:
			results = append(results, []string{name, "TAMPERED", path})
			RegisterFinding("drivers", name, fmt.Sprintf("Kernel driver has a tampered/invalid signature: %s (%s)", name, path), 90, "T1036.001")
		case !sig.Signed:
			sev := 30
			if !inSystem32Drivers {
				sev = 65
			}
			results = append(results, []string{name, "Unsigned", path})
			RegisterFinding("drivers", name, fmt.Sprintf("Unsigned kernel driver loaded: %s (%s, state=%s)", name, path, state), sev, "T1547.006")
		case !inSystem32Drivers:
			results = append(results, []string{name, "Non-standard path", path})
			RegisterFinding("drivers", name, "Signed driver loaded from a non-standard path: "+path, 20, "T1547.006")
		}
	}

	if len(results) == 0 {
		results = append(results, []string{"No driver issues found", "Clean", "Test signing off, all loaded drivers signed and in System32\\drivers"})
	}

	return results
}

func resolveDriverPath(raw, systemRoot string) string {
	p := raw
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, `\systemroot\`):
		p = systemRoot + p[len(`\SystemRoot`):]
	case strings.Contains(p, ":\\") || strings.Contains(p, ":/"):
		// already absolute
	default:
		p = systemRoot + `\` + strings.TrimPrefix(p, `\`)
	}
	return p
}
