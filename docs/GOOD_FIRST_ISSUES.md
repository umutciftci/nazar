# Suggested seed issues (copy into GitHub Issues)

Use these as templates when opening the first `good first issue` tickets after `v0.1.0`.

---

**Title:** `feat(parser): add Maven (pom.xml) support`

**Labels:** `enhancement`, `good first issue`, `ecosystem:java` (create label if needed), `area:parser`

**Body:**

Add a Maven parser under `internal/parser/` and wire detection in `internal/scanner/scanner.go`.

- Parse resolved versions from `pom.xml` (or document if only lockfile-based resolution is feasible)
- OSV ecosystem: `Maven`
- Include at least one `_test.go` fixture
- Update README "Supported ecosystems" table

---

**Title:** `feat(scan): add --exclude-ecosystem flag`

**Labels:** `enhancement`, `good first issue`, `area:scanner`

**Body:**

Allow `nazar scan` to skip entire ecosystems, e.g. `--exclude-ecosystem npm`.

- Flag on `nazar scan` and `nazar ci`
- Document in README
- Add a small unit or integration test

---

**Title:** `fix(show): improve output when OSV returns no severity`

**Labels:** `bug`, `good first issue`, `area:osv`

**Body:**

When `nazar show <id>` returns a record without severity metadata, the output should still be useful (ID, summary, affected packages if any).

Include a test with a mocked OSV response.

---

**Title:** `test(parser): add Composer v1 lockfile fixtures`

**Labels:** `good first issue`, `area:parser`, `ecosystem:php`

**Body:**

Add realistic `composer.lock` v1 fixtures under `internal/parser/testdata/` and ensure the PHP parser handles them.

---

**Title:** `docs: document nazar fix --rollback with a worked example`

**Labels:** `documentation`, `good first issue`, `area:fixer`

**Body:**

Expand README `nazar fix` section with a step-by-step rollback example showing backup path under `~/.cache/nazar/fix-backups/`.
