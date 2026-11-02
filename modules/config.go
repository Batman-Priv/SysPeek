package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Config struct {
	TrustedPublishers []string `json:"trusted_publishers"`
	HijackTargets     []string `json:"hijack_targets"`
	LsassAllowlist    []string `json:"lsass_allowlist"`
	Thresholds        struct {
		Low    int `json:"low"`
		Medium int `json:"medium"`
		High   int `json:"high"`
	} `json:"thresholds"`
}

var (
	cfg      Config
	cfgOnce  sync.Once
	cfgMu    sync.RWMutex
)

func defaultConfig() Config {
	c := Config{
		TrustedPublishers: []string{
			"Microsoft", "Google", "NVIDIA", "AMD", "Intel",
			"VMware", "Discord", "Mozilla", "Adobe", "Valve",
			"GitHub", "Epic Games", "Ubisoft", "Activision",
			"Blizzard", "Apple Inc", "Oracle", "JetBrains",
			"Slack", "Zoom", "Cisco", "Fortinet", "Dropbox",
			"Docker", "Spotify", "Notion", "1Password", "Postman",
		},
		HijackTargets: []string{
			"version.dll", "dbghelp.dll", "dbgcore.dll", "winhttp.dll",
			"wow64log.dll", "profapi.dll", "uxtheme.dll", "cryptbase.dll",
			"sensapi.dll", "wtsapi32.dll", "ntmarta.dll", "secur32.dll",
			"dwmapi.dll", "amsi.dll", "userenv.dll", "propsys.dll", "iphlpapi.dll",
		},
		
		LsassAllowlist: []string{
			"wmiprvse.exe", "svchost.exe", "csrss.exe", "werfault.exe",
			"vmtoolsd.exe", "procexp.exe", "procexp64.exe", "taskmgr.exe",
		},
	}
	c.Thresholds.Low = 20
	c.Thresholds.Medium = 50
	c.Thresholds.High = 80
	return c
}

func configPath() string {
	if p := os.Getenv("SYSPEEK_CONFIG"); p != "" {
		return p
	}
	if exePath, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exePath), "syspeek_config.json")
	}
	return "syspeek_config.json"
}

func LoadConfig() Config {
	cfgOnce.Do(func() {
		cfgMu.Lock()
		defer cfgMu.Unlock()

		cfg = defaultConfig()
		data, err := os.ReadFile(configPath())
		if err != nil {
			return 
		}

		var override Config
		if err := json.Unmarshal(data, &override); err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s is invalid JSON, ignoring and using defaults: %v\n", configPath(), err)
			return
		}

		if len(override.TrustedPublishers) > 0 {
			cfg.TrustedPublishers = override.TrustedPublishers
		}
		if len(override.HijackTargets) > 0 {
			cfg.HijackTargets = override.HijackTargets
		}
		if len(override.LsassAllowlist) > 0 {
			cfg.LsassAllowlist = override.LsassAllowlist
		}
		if override.Thresholds.Low > 0 {
			cfg.Thresholds.Low = override.Thresholds.Low
		}
		if override.Thresholds.Medium > 0 {
			cfg.Thresholds.Medium = override.Thresholds.Medium
		}
		if override.Thresholds.High > 0 {
			cfg.Thresholds.High = override.Thresholds.High
		}
	})

	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg
}

func GetConfig() Config {
	return LoadConfig()
}

func WriteDefaultConfig(path string) (string, error) {
	if path == "" {
		path = configPath()
	}
	data, err := json.MarshalIndent(defaultConfig(), "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}
