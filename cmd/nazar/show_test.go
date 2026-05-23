package main

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunShow_InvalidID(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := runShow(cmd, "NONSENSE-1234", "", "https://api.osv.dev", true)
	if err == nil {
		t.Fatal("expected error for invalid vulnerability ID")
	}
	if !strings.Contains(err.Error(), "no OSV record") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestErrVulnsFound_Message(t *testing.T) {
	e := &errVulnsFound{count: 1, threshold: "high"}
	if got := e.Error(); got != "1 vulnerability at or above high found (--fail-on triggered)" {
		t.Fatalf("got %q", got)
	}
	e.count = 3
	if !strings.Contains(e.Error(), "3 vulnerabilities") {
		t.Fatalf("got %q", e.Error())
	}
}
