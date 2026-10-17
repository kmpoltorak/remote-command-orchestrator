# RCO — Remote Command Orchestrator

RCO runs one change (commands, scripts, file uploads) over SSH on many Linux
hosts in parallel and reports the result for each host. It is built for small
devices on unreliable links, such as LTE routers: it needs only a POSIX shell
on the host, no agent and no Python.

```text
$ rco run -i hosts.yaml -j jobs/configure-ntp -g web --execute
HOST     STATUS   FAILED STEP  REASON                                   DURATION
web-01   SUCCESS  -            -                                        2.41s
web-02   FAILED   verify       output does not contain "ntp1.example"   2.52s

2 hosts: 1 succeeded, 1 failed, 0 cancelled in 2.53s (job configure-ntp, sha256 4be1c07e93aa)
```

Safety rules:

- `rco run` only previews. Nothing runs on a host without `--execute`.
- All hosts are validated (variables, templates, credentials) before any is contacted.
- Host keys are checked against `known_hosts`. Secrets never live in files and are masked in output.
- Every job sets `max_failures`: after that many failed hosts, no new host starts.

## Install

Download a binary for Linux (amd64, arm64, armv7) or macOS from
[Releases](https://github.com/kmpoltorak/remote-command-orchestrator/releases), or:

```bash
go install github.com/kmpoltorak/remote-command-orchestrator/cmd/rco@latest
```

Hosts need `sh`, `mktemp`, `dirname`, `cp`, `chmod` and `mv` (busybox is
enough), plus `bash` for `script:` steps and `sudo` for `sudo:` steps.

## Quick start

`hosts.yaml`:

```yaml
credentials:
  deploy-key: {type: private_key, username: deploy, key_file: ~/.ssh/deploy_ed25519}
defaults:
  credential: deploy-key
groups:
  web:
    hosts:
      - {name: web-01, address: 192.0.2.10}
      - {name: web-02, address: 192.0.2.11}
```

`jobs/uptime/job.yaml`:

```yaml
name: uptime
max_failures: "100%"
steps:
  - name: uptime
    command: uptime
```

```bash
rco validate -j jobs/uptime -i hosts.yaml              # check, no connections
rco run -i hosts.yaml -j jobs/uptime                   # preview
rco run -i hosts.yaml -j jobs/uptime --execute -v      # run, show output
```

Hosts must already be in `~/.ssh/known_hosts`, or pass `--accept-new-host-keys`
to add unknown ones (changed keys are still rejected). More examples are in
[`examples/`](examples/).

## Job file

`-j` takes a job directory (with `job.yaml`) or a YAML file. Steps run in
order on each host over one connection. A failed step stops that host.

```yaml
name: configure-ntp
max_failures: "5%"             # required: number of hosts ("5") or share ("5%")
variables:
  ntp_server: {required: true}
defaults:                      # apply to every step
  timeout: 60s
  sudo: true
steps:
  - name: install
    command: apt-get install -y chrony
    retries: 2
  - name: config
    copy: {src: files/chrony.conf.tmpl, dest: /etc/chrony/chrony.conf, mode: "0644", template: true}
  - name: restart
    script: scripts/restart-chrony.sh     # runs with bash; variables exported as $ntp_server
  - name: verify
    sudo: false
    command: chronyc -n sources
    expect: {contains: "{{ .ntp_server }}"}
```

Each step has one of `command`, `script` or `copy`. `copy` writes a temp file
next to `dest` and renames it, so readers never see a partial file. Paths are
relative to the job file.

| Step option | Meaning |
|---|---|
| `sudo` | run as root |
| `timeout` | kill the command after this long (default 5m) |
| `retries`, `retry_delay` | re-run a failed step |
| `continue_on_error` | keep going; the host is still reported as failed |
| `expect` | `exit_code` (default 0), `contains`, `not_contains`, `regex` |
| `sensitive` | hide the command and output |
| `reboot` | the command reboots the host; wait until it is back with a new boot ID |
| `disconnect` | the command may drop the connection (network restart); reconnect and continue |
| `reconnect_timeout` | how long to wait after `reboot` (default 10m) or `disconnect` (default 5m) |
| `fire_and_forget` | start the command in the background and check nothing (e.g. a SIM switch); last step only |

`reboot`, `disconnect` and `fire_and_forget` steps never retry, so the command
never runs twice.

**OpenWrt:** log in as `root`, don't use `sudo`, and use `command:` and `copy:`
(`script:` needs bash). See `examples/jobs/openwrt-sim-switch`.

### Variables

Write `{{ .name }}` in `command`, `copy.dest`, `expect` and templated files.
Values come from, highest priority first:

1. `--var name=value` or `--var-env name=ENV_VAR`
2. inventory `variables` (host, then group, then inventory defaults)
3. `default:` in the job

A `--var` the job doesn't declare is an error. Values are inserted into shell
commands as they are, so only use trusted values.

**Secrets:** declare the variable `sensitive: true`, pass it with `--var-env`,
and mark every step that uses it `sensitive: true`. RCO replaces passwords,
passphrases and `--var-env` values with `[REDACTED]` everywhere.

## Inventory

```yaml
credentials:                       # only references; secrets come from the environment
  deploy-key:
    type: private_key
    username: deploy
    key_file: ~/.ssh/deploy_ed25519
    passphrase_env: DEPLOY_KEY_PASSPHRASE   # encrypted key only
    sudo_password_env: DEPLOY_SUDO_PASSWORD # omit for passwordless sudo
  legacy:
    type: password
    username: admin
    password_env: LEGACY_PASSWORD           # also used for sudo
bastions:
  jump: {address: bastion.example.com, credential: deploy-key}
defaults:
  credential: deploy-key
groups:
  web:
    defaults: {variables: {ntp_server: ntp1.example.com}}
    hosts:
      - {name: web-01, address: 192.0.2.10, tags: [canary]}
      - {name: web-02, address: 192.0.2.11, port: 2222}
  internal:
    defaults: {bastion: jump}
    hosts:
      - {name: db-01, address: 198.51.100.5}
```

Host settings override group defaults, which override inventory defaults.
Select hosts with `-g GROUP`, `-t TAG` and `-H HOST` (repeatable; OR within a
kind, AND across kinds; none selects all). Keep one inventory per environment
and combine shared files with repeated `-i`.

## Running

Run `rco help` for every option. The ones you'll use most:

| Option | Meaning |
|---|---|
| `--execute` | actually run (otherwise preview) |
| `-c N` | hosts at the same time (default 100) |
| `-o json\|yaml` | machine-readable output on stdout; logs go to stderr |
| `--report FILE` | save the report (`.json`, `.yaml`, or `.jsonl` written host by host) |
| `--only-failed REPORT` | rerun only the hosts that did not succeed |
| `--max-failures N` | override the job's `max_failures` |

Exit codes: `0` all hosts succeeded, `1` invalid input (no host contacted),
`2` some host failed, was skipped or was cancelled. Ctrl+C starts no new hosts,
cancels the running ones and still writes the report.

A typical rollout:

```bash
rco run -i prod.yaml -j jobs/x -t canary --execute
rco run -i prod.yaml -j jobs/x --execute --report run.jsonl
rco run -i prod.yaml -j jobs/x --execute --only-failed run.jsonl
```

## Limitations

- Linux-like hosts only.
- No ssh-agent and no `~/.ssh/config`: everything is in the inventory.
- No automatic rollback: write jobs that can safely run twice.
- Not yet tested: a bastion with many parallel tunnels on a real sshd.

## Development

```bash
make check         # format, vet, tests with -race, build
make lint          # golangci-lint
make integration   # tests against Docker containers (OpenSSH, and dropbear with busybox)
```

Unit tests run against an in-process SSH server that can drop connections,
hang, and fake reboots. Pushing a `v*` tag publishes a release. Keep personal
inventories in `local/` (git-ignored).

Built with an AI coding assistant. I wrote the spec and reviewed every change.

## License

MIT, see [LICENSE](LICENSE).
