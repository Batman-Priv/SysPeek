package utils

import (
	"os"

	"github.com/olekukonko/tablewriter"
)

func RenderTable(title string, headers []string, data [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoMergeCells(true)
	table.SetRowSeparator("-")
	table.SetCenterSeparator("│")
	table.SetColumnSeparator("│")
	table.SetTablePadding("\t")

	colors := make([]tablewriter.Colors, len(headers))
	for i := range colors {
		colors[i] = tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor}
	}
	table.SetHeaderColor(colors...)
	for _, row := range data {
		rowColors := make([]tablewriter.Colors, len(row))
		for i := range rowColors {
			rowColors[i] = tablewriter.Colors{}

			if i == 2 { 
				if row[i] == "No" || row[i] == "Not Found" || row[i] == "Not Verified" {
					rowColors[i] = tablewriter.Colors{tablewriter.FgRedColor}
				} else if row[i] == "Yes" || row[i] == "Active" || row[i] == "Verified" {
					rowColors[i] = tablewriter.Colors{tablewriter.FgGreenColor}
				}
			}
			
			if i == 3 { 
				if row[i] != "None" && row[i] != "N/A" && row[i] != "Clean" {
					rowColors[i] = tablewriter.Colors{tablewriter.FgYellowColor}
				}
			}
		}
		table.Rich(row, rowColors)
	}
	
	table.Render()
}