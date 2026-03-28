# iron-sensor

An eBPF-based behavioral monitor for AI coding agents. iron-sensor detects when AI agents like Claude Code, Codex, and OpenClaw are running on a Linux system, then monitors every process they spawn, every file they touch, and every persistence mechanism they attempt.

## Why this exists

AI coding agents run with your credentials, in your shell, on your infrastructure. They can do anything you can: read SSH keys, write cron jobs, modify systemd units, and escalate privileges. Most of the time, this helps you code. Some of the time, this installs a backdoor that exfiltrates your credentials. There is no way of telling which it is by default. iron-sensor solves that problem.

iron-sensor sits in the kernel via eBPF and watches what these agents actually do. Since it works in kernel-space, it is nearly zero overhead. It doesn't block anything. Rather, it emits structured events as NDJSON so you can see, alert on, and audit agent behavior.

## Getting started

### Download

Grab the latest pre-built binary from the [GitHub Releases](https://github.com/ironsh/iron-sensor/releases/latest) page:

```sh
curl -Lo iron-sensor.tar.gz https://github.com/ironsh/iron-sensor/releases/latest/download/iron-sensor_linux_amd64.tar.gz
tar xzf iron-sensor.tar.gz
sudo mv iron-sensor /usr/local/bin/
```

### Build from source

**Prerequisites:**

- Linux with kernel BTF support (5.8+)
- Root privileges (BPF requires CAP_BPF/CAP_SYS_ADMIN)
- Go 1.25+
- clang, llvm, libbpf-dev (for BPF compilation)
- [just](https://github.com/casey/just) command runner

On Ubuntu/Debian:

```sh
sudo apt-get install clang llvm libbpf-dev
```

```sh
just build
```

This compiles the eBPF programs, generates Go bindings, and builds the `bin/iron-sensor` binary.

### Run

```sh
# With default config (file sink to /var/log/iron/sensor/events.json)
sudo ./bin/iron-sensor

# With a config file
sudo ./bin/iron-sensor --config examples/config.example.yaml

# Development mode (stdout)
sudo ./bin/iron-sensor --config config.dev.yaml
```

### Install as a service

```sh
sudo cp bin/iron-sensor /usr/local/bin/
sudo mkdir -p /etc/iron-sensor
sudo cp examples/config.example.yaml /etc/iron-sensor/config.yaml
sudo cp examples/iron-sensor.service /etc/systemd/system/
sudo systemctl enable --now iron-sensor
```

## Configuration

iron-sensor is configured via a YAML file passed with `--config`. See [config.example.yaml](examples/config.example.yaml) for all options.

```yaml
sink_type: file

file_sink:
  output_path: /var/log/iron/sensor/events.json
  max_size: 100       # MB before rotation
  max_backups: 5
  compress: true

rules:
  min_severity: 1     # only emit alert and warn (drop info)
  overrides:
    package_manager:
      enabled: false   # suppress package manager events
    shell_spawn:
      severity: 2      # downgrade to info
```

Severity levels: `0` = alert, `1` = warn, `2` = info. The `min_severity` filter drops events above the threshold. Agent lifecycle events (start/stop) are always emitted regardless of filter.

When no `--config` is provided, iron-sensor uses sensible defaults (file sink, all rules enabled, no severity filter).

## Event format

Events are emitted as newline-delimited JSON. Example:

```json
{"event_id":"01J...","ts":"2025-01-15T10:30:00.000Z","category":"process","severity":1,"pid":12345,"ppid":12340,"comm":"curl","exe":"/usr/bin/curl","argv":["curl","https://example.com"],"cwd":"/home/user/project","agent_root_pid":12300,"in_agent_subtree":true,"rule_matched":"network_tool"}
```

**Categories:** `agent_lifecycle`, `process`, `file`, `persistence`

## How it works

iron-sensor attaches to six kernel tracepoints:

| Tracepoint | What it captures |
|---|---|
| `sched/sched_process_exec` | Every process execution — detects new agents and child processes |
| `sched/sched_process_fork` | Parent-child relationships — tracks the full agent process tree |
| `sched/sched_process_exit` | Process exits — emits lifecycle events with duration and exit codes |
| `syscalls/sys_enter_openat` + `sys_exit_openat` | File opens — captures path, flags, and file descriptor |
| `syscalls/sys_enter_fchmodat` | Permission changes — detects setuid/setgid bit manipulation |

When an agent is detected (via executable name and argv matching), iron-sensor registers it in a BPF hash map. The kernel-side program then propagates tracking to every child process the agent forks, building a complete subtree. All activity within that subtree — process spawns, file access, persistence writes — is emitted as classified, severity-tagged NDJSON events.

### Agent detection

| Agent | How it's identified |
|---|---|
| Claude Code | `argv[0]` basename is `claude` |
| OpenClaw | `argv[0]` basename is `openclaw-gateway` |
| Codex | Executable is `python3` and argv contains `codex` |

Detection works both at startup (scanning `/proc`) and live (via the exec tracepoint).

#### Custom binary detections

You can configure additional binary detections via the `detections` section in your config file. Each entry matches on the basename of `argv[0]`, the same way the built-in Claude Code and OpenClaw detections work.

```yaml
detections:
  binaries:
    - name: exfil_agent
      binary: exfil-tool
    - name: custom_assistant
      binary: my-ai-agent
```

| Field | Description |
|---|---|
| `name` | Signature name that appears in emitted events (`signature_matched`) |
| `binary` | Basename of `argv[0]` to match (e.g. `my-agent` matches `/usr/local/bin/my-agent`) |

Custom detections are appended to the built-in set — built-in agents are always detected regardless of config.

### Detection rules

Events are classified by a rule engine with three categories. First match wins within each category.

**Process rules** — applied to any process spawned within an agent subtree:

| Rule | Severity | Triggers on |
|---|---|---|
| `privilege_escalation` | Alert | sudo, su, doas |
| `ptrace_tool` | Alert | strace, ltrace, gdb |
| `network_tool` | Warn | curl, wget, nc, ncat, socat |
| `interpreter_exec` | Warn | python/ruby/perl/node spawned by a shell |
| `shell_spawn` | Warn | sh, bash, zsh, dash, fish |
| `package_manager` | Info | apt, pip, npm, yarn, gem, cargo |

**Persistence rules** — checked first on file events; a match re-categorizes the event:

| Rule | Severity | Paths |
|---|---|---|
| `ssh_persistence` | Alert | authorized_keys, ssh config, sshd_config |
| `cron_write` | Alert | /etc/cron\*, /var/spool/cron/\* |
| `systemd_unit_write` | Alert | /etc/systemd/\*, ~/.config/systemd/\* |
| `system_profile_write` | Alert | /etc/profile, /etc/environment |
| `ld_preload_write` | Alert | /etc/ld.so.preload, /etc/ld.so.conf.d/\* |
| `sudoers_write` | Alert | /etc/sudoers, /etc/sudoers.d/\* |
| `shell_rc_write` | Warn | .bashrc, .zshrc, .profile, etc. |
| `xdg_autostart` | Warn | ~/.config/autostart/\*, /etc/xdg/autostart/\* |
| `apt_hook` | Warn | /etc/apt/apt.conf.d/\* |
| `npmrc_write` | Warn | .npmrc |
| `git_hook_write` | Warn | .git/hooks/\* |

**File rules** — applied to file opens not caught by persistence rules:

| Rule | Severity | Triggers on |
|---|---|---|
| `ssh_key_access` | Alert | Any access to ~/.ssh/ |
| `proc_mem_access` | Alert | /proc/\*/mem, /proc/\*/environ |
| `docker_socket` | Alert | docker.sock, containerd paths |
| `cgroup_write` | Alert | /sys/fs/cgroup/\* writes |
| `sensitive_file_write` | Alert | /etc/shadow, /etc/passwd, etc. writes |
| `sensitive_file_read` | Warn | Same paths, read-only |
| `generic_write` | Info | Any file write |

## Testing

```sh
# Unit tests
just test

# End-to-end tests (requires root + BPF)
sudo go test -tags e2e -v -count=1 ./test/e2e/
```

The e2e tests boot the real sensor, launch stub binaries that mimic each agent, perform detectable actions (reading /etc/shadow, writing cron jobs, spawning curl), and assert that the correct events fire.

## What about network egress?

iron-sensor intentionally does not monitor network egress. Meaningful egress control for AI agents requires SNI-aware proxying that inspects TLS ClientHello to determine where connections are going and enforcing policy on a per-destination basis. That's a fundamentally different architecture from kernel-level file and process monitoring.

Network egress monitoring and policy enforcement are features of the broader [iron.sh](https://iron.sh) platform.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
