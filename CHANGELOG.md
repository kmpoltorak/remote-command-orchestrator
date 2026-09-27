# Changelog

All notable changes to RCO. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.2] - 2026-09-27

### Added
- Integration tests against a disposable Docker container (`make integration`), run in CI
  as a separate job, plus `shellcheck` and `hadolint`.
- `CLAUDE.md`, `.env.example` and `docs/review-log.md`.

### Changed
- The tool is called RCO in the docs and `rco help`; the command is still `rco`.
- README reordered (Problem, Why not Ansible?, Quick start, …, Testing, How this was built).
- Example and test addresses use RFC 5737 ranges.

## [1.0.1] - 2026-09-27

### Security
- `copy` steps write through a fresh `mktemp` file next to `dest` instead of the fixed
  name `dest.rco-tmp`, which GNU `cp` followed if it was a symlink, as root with sudo.
- `--var-env` values are masked in the commands shown in the preview and reports, also
  for variables not declared `sensitive`.

### Fixed
- The step timeout and Ctrl+C now also cover opening the SSH session and the exec
  request; a hung server no longer blocks the run.
- A preview (`rco run` without `--execute`) no longer truncates and deletes an existing
  `.jsonl` report.
- `defaults.retries` no longer re-runs `reboot`, `disconnect` or `fire_and_forget` steps.
- `fire_and_forget` and `disconnect` steps fail when the host refuses to start the
  command, instead of reporting success.

### Changed
- README: install without `GOPRIVATE` (the repository is public); new "Why not Ansible?"
  section.

## [1.0.0] - 2026-09-25

First release: static binaries for Linux (amd64, arm64, armv7) and macOS.

- Jobs with `command`, `script` and `copy` steps, sudo per step, expectations
  (`exit_code`, `contains`, `not_contains`, `regex`), retries and timeouts.
- Preview by default; changes are applied only with `--execute`.
- Host keys checked against `known_hosts`; `--accept-new-host-keys` for trust on first use.
- `reboot`, `disconnect` and `fire_and_forget` steps for commands that drop the connection.
- Required `max_failures` in every job, `--only-failed`, streamed `.jsonl` reports and
  progress logging for large fleets.
- One shared connection per bastion for the whole run.

[Unreleased]: https://github.com/kmpoltorak/remote-command-orchestrator/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/kmpoltorak/remote-command-orchestrator/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/kmpoltorak/remote-command-orchestrator/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kmpoltorak/remote-command-orchestrator/releases/tag/v1.0.0
