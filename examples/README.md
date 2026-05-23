# Integration examples

Copy-paste samples for running nazar in CI and local hooks.

| Example | Path | Description |
|---------|------|-------------|
| GitHub Actions | [github-actions/nazar-ci.yml](github-actions/nazar-ci.yml) | Scan on push/PR, upload SARIF |
| GitLab CI | [gitlab-ci/.gitlab-ci.yml](gitlab-ci/.gitlab-ci.yml) | Scan stage with SARIF artifact |
| pre-commit | [pre-commit/.pre-commit-hooks.yaml](pre-commit/.pre-commit-hooks.yaml) | Run `nazar ci` on pre-push |

For production pipelines, prefer installing a pinned release binary from [GitHub Releases](https://github.com/umutciftci/nazar/releases) instead of `@latest`.
