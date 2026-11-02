package modules

import (
	"os"
	"strconv"
	"runtime"
	"strings"
)

func GetEnvironmentInfo() [][]string {
	var results [][]string

	if runtime.GOOS == "windows" {
		path := os.Getenv("PATH")
		pathParts := strings.Split(path, ";")
		results = append(results, []string{"Environment", "PATH Entries", strconv.Itoa(len(pathParts))})
		results = append(results, []string{"Environment", "PATH", strings.Join(pathParts[:5], "; ") + "..."})

		temp := os.Getenv("TEMP")
		results = append(results, []string{"Environment", "TEMP", temp})
		
		systemRoot := os.Getenv("SystemRoot")
		results = append(results, []string{"Environment", "SystemRoot", systemRoot})
		
		processorArch := os.Getenv("PROCESSOR_ARCHITECTURE")
		results = append(results, []string{"Environment", "Processor Arch", processorArch})
		
		numberOfProcessors := os.Getenv("NUMBER_OF_PROCESSORS")
		results = append(results, []string{"Environment", "Number of Processors", numberOfProcessors})

	} else if runtime.GOOS == "linux" {
		path := os.Getenv("PATH")
		pathParts := strings.Split(path, ":")
		results = append(results, []string{"Environment", "PATH Entries", strconv.Itoa(len(pathParts))})
		results = append(results, []string{"Environment", "PATH", strings.Join(pathParts[:5], ":") + "..."})

		home := os.Getenv("HOME")
		results = append(results, []string{"Environment", "HOME", home})
		
		user := os.Getenv("USER")
		results = append(results, []string{"Environment", "USER", user})
		
		shell := os.Getenv("SHELL")
		results = append(results, []string{"Environment", "SHELL", shell})
		
		lang := os.Getenv("LANG")
		results = append(results, []string{"Environment", "LANG", lang})
	}

	return results
}