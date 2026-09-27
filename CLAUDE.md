# CLAUDE.md

This repo is one of my ops tools. They are built with AI coding assistants: I own the
problem, the spec, the review and the verification; the assistant writes most of the code.
The point of every rule below is that the result must not be AI slop: small, correct,
tested where it matters, and honestly documented.

## This project

- **Problem:** pushing one configuration change (commands, scripts, files) over SSH to
  many small Linux devices, such as LTE routers at remote sites, and knowing exactly
  which hosts got it. Some changes cut their own uplink (SIM switch, network restart,
  reboot), and links drop silently.
- **Existing tools and why they don't fit:** Ansible can hang on a silently dropped
  connection, its default `linear` strategy waits for the slowest host, and most modules
  need Python, which OpenWrt/RutOS don't ship. Plain `ssh` loops have no concurrency
  limit, no verification and no report.
- **Runs where / against what:** a single static Go binary (`rco`) on the operator's
  Linux or macOS machine. Targets are Linux-like hosts with a POSIX shell (`bash` only
  for `script:` steps), including OpenWrt 23.05 with dropbear, optionally behind a
  bastion, often on flaky LTE links.
- **Trust boundaries:** job files and inventories (validated in full before any host is
  contacted; templates are plain `{{ .var }}` lookups; control characters rejected);
  secrets from environment variables (never stored, masked in all output); remote hosts
  (host keys verified against `known_hosts`, output size-limited and treated as data,
  every step bounded by a timeout); the remote filesystem (uploads go through private
  `mktemp` files, never fixed paths); report files (mode 0600).
- **Out of scope:** no server, API, database, queue or notifications; no Kubernetes; no
  interactive prompts / PTY for network devices; no Windows targets; no idempotent
  modules or state management: it runs the steps you write, it is not a configuration
  management system.

## Workflow

1. **Spec before code.** For any non-trivial change, write a short plan first (what, why,
   what could break, how it will be tested) and wait for my approval.
2. **Branch + PR, never `main`.** One logical change per PR. The PR description says what
   changed, why, and how it was verified.
3. **Ask, don't guess,** when the spec is ambiguous or a change touches a trust boundary.
4. **Record review decisions.** When I reject or change something you proposed, append one
   line to `docs/review-log.md`:
   `YYYY-MM-DD · PR #n · what was proposed · what I decided · why`.
   This log is the source for the "How this was built" section. Never invent entries.

## Minimal code (ponytail)

Ponytail is installed as a plugin. Before opening a PR, run `/ponytail-review` on the diff
and apply what it finds. Run `/ponytail-audit` on the whole repo before each release.

Prefer, in order: no code → existing code in this repo → standard library → a
well-known dependency → new code. Every new dependency needs one sentence of
justification in the PR.

**Never removed for the sake of brevity** (ponytail or otherwise):
- timeouts, retries, keepalives, cancellation and cleanup on network and process boundaries
- validation of anything crossing a trust boundary (input, remote output, LLM output)
- error handling that prevents data loss, partial writes or silent failures
- secret masking and security checks
- tests

If a shortcut is taken deliberately, mark it with a `ponytail:` comment explaining the
trade-off, so `/ponytail-debt` can find it.

## Testing

- **Every test must be able to fail.** When adding a test for a behavior, break that
  behavior on purpose, confirm the test fails, restore it, and say so in the PR
  ("sabotage check: removed X → test Y failed").
- **Test the failure modes of the domain,** not just the happy path: timeouts, silent
  connection drops, partial or malformed output, unreachable hosts, invalid LLM responses.
- No tests that only assert a mock was called. Assert observable behavior.
- Unit tests are deterministic and never touch the network. Integration tests live
  behind a build tag / marker and use disposable containers.
- Never skip, weaken or delete a failing test to make CI green. Fix the code or ask.

## CI (must be green before merge)

- **Go:** `gofmt`, `go vet`, `golangci-lint`, `go test -race ./...`, `govulncheck`
- **Python:** `ruff check`, `ruff format --check`, `pytest`, `pip-audit`
- **Shell / Docker:** `shellcheck`, `hadolint`
- Integration tests in a separate job.

## Data hygiene

- Only example data: `example.com` / `example.net`, RFC 5737 addresses
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), invented host and site names.
- No real hostnames, topologies, device counts, logs or configs from any employer.
- No secrets in the repo. Provide `.env.example`; secrets come from the environment.

## README structure

Keep this order. Write in plain English, no marketing.

1. **Title + one sentence:** what it does.
2. **Problem:** the real situation that caused it (2–4 sentences).
3. **Why not <existing tool>?** Fair comparison. Say what the existing tool can do
   with tuning; say what this tool makes the default.
4. **Quick start:** copy-paste commands that work on a clean machine.
5. **Usage / configuration.**
6. **Limitations:** what it does not handle, honestly.
7. **Testing:** how to run the tests and what failure modes they cover.
8. **How this was built:** template below.
9. **License.**

Every claim in the README must be backed by code or a test. If you cannot point to it,
remove the claim. No invented benchmarks or numbers.

### "How this was built" template

```markdown
## How this was built

Built with an AI coding assistant. I wrote the problem statement and spec, reviewed
every PR, and designed the checks below.

**Spec:** <one paragraph: the constraints I set, e.g. "must not hang on a dead
connection", "LLM output is never trusted without validation">

**What I changed or rejected in review:** (from docs/review-log.md)
- <concrete decision + why, link to PR>
- <concrete decision + why, link to PR>

**What the tests are there to catch:**
- <failure mode> → <test name>, sabotage-checked

**What I don't trust yet / known gaps:**
- <honest gap>
```

Draft this section from `docs/review-log.md` and the tests. Leave placeholders for
anything I haven't decided. Never fill it with plausible-sounding invented decisions.

## Definition of done

- [ ] Spec approved, change on a branch, PR opened
- [ ] `/ponytail-review` applied, protected list untouched
- [ ] New behavior has a sabotage-checked test
- [ ] CI green
- [ ] README updated; every new claim backed by code or a test
- [ ] Review decisions logged in `docs/review-log.md`
