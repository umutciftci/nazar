package main

import "github.com/charmbracelet/lipgloss"

// Shared lipgloss styles used across diff, watch, show, and fix commands.
var (
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7B68EE")).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Italic(true)

	ecosystemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7B68EE")).
			Bold(true)
)
