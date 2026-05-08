package parser

import (
	"testing"
)

func TestParseComposerLock(t *testing.T) {
	pkgs, err := ParseComposerLock("testdata/composer.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2 prod packages + 1 dev package = 3 total.
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}

	byName := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// Production packages are Direct.
	guzzle, ok := byName["guzzlehttp/guzzle"]
	if !ok {
		t.Fatal("missing guzzlehttp/guzzle")
	}
	if guzzle.Version != "7.8.1" {
		t.Errorf("guzzle version: got %q, want 7.8.1", guzzle.Version)
	}
	if !guzzle.Direct {
		t.Error("guzzle should be Direct (production dep)")
	}

	// "v" prefix in composer.lock must be stripped.
	symfony, ok := byName["symfony/console"]
	if !ok {
		t.Fatal("missing symfony/console")
	}
	if symfony.Version != "6.4.0" {
		t.Errorf("symfony/console version: got %q, want 6.4.0 (v prefix stripped)", symfony.Version)
	}
	if !symfony.Direct {
		t.Error("symfony/console should be Direct")
	}

	// Dev packages are not Direct.
	phpunit, ok := byName["phpunit/phpunit"]
	if !ok {
		t.Fatal("missing phpunit/phpunit")
	}
	if phpunit.Direct {
		t.Error("phpunit/phpunit should not be Direct (dev dep)")
	}
}

func TestParseComposerLock_NotExist(t *testing.T) {
	_, err := ParseComposerLock("testdata/nonexistent.lock")
	if err == nil {
		t.Fatal("expected an error for missing file")
	}
}
