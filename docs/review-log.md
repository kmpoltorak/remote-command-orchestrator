# Review log

One line per proposal the maintainer rejected or changed in review. Source for the
"How this was built" section of the README. Only real decisions; never invented.

`YYYY-MM-DD · PR #n · what was proposed · what I decided · why`

- 2026-09-24 · before PR #1 · a full platform: history database, REST server, job queue, notifications, interactive prompts for network devices · a Linux-only CLI (`run`/`validate`), results on stdout plus an optional report file · the platform was overkill for pushing configuration to Linux hosts
- 2026-09-25 · PR #1 · running the tool against my LAN host from the assistant's session · rejected; the assistant writes the steps, I run them · nothing touches a real host except by my hand
- 2026-09-25 · PR #1 · commit and push each fix as it is made · one branch, one PR when everything is fixed · a PR should be one reviewable change
- 2026-09-25 · PR #2 · one general reconnect mechanism (with an `expect.rebooted`-style check) for steps that lose the connection · three simple flags: `reboot`, `disconnect`, `fire_and_forget` · the general version was too complex to reason about
- 2026-09-25 · PR #2 · `--max-failures` as an optional command-line flag · `max_failures` required in every job file; the flag only overrides it · whoever writes the job must decide how much breakage is acceptable
- 2026-09-27 · PR #4 · README install section saying the repository is private, with `GOPRIVATE` · removed; plain `go install …@latest` · the repository is public
- 2026-09-27 · PR #5 · README claims "tested against OpenWrt 23.05" and "tested with 100 hosts and 50 parallel tunnels" · removed as hallucinations · no test in the repo backs them
- 2026-09-27 · PR #5 · no CHANGELOG (decided earlier) · add `CHANGELOG.md` · users of the binaries need to see what changed between releases
