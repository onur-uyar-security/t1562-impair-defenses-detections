# 03 · Prevent Command History Logging

| Field | Value |
|---|---|
| Legacy ID | T1562.003 Impair Defenses: Impair Command History Logging |
| Current ID | **T1690** Prevent Command History Logging |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Linux, macOS, ESXi, Windows (PowerShell), network devices |
| Data sources | auditd (EXECVE, SYSCALL), EDR process telemetry, PowerShell Script Block Logging (4104), file integrity monitoring |
| Suggested severity | Medium (High on production servers) |

## What the adversary does

Stops the shell from recording commands, so an investigator who later reads `~/.bash_history` or the PowerShell history file finds nothing:

- Linux/macOS: `unset HISTFILE`, `export HISTSIZE=0`, `HISTCONTROL=ignorespace` (then prefixing commands with a space), `set +o history`, or linking the history file to `/dev/null`
- PowerShell: `Set-PSReadLineOption -HistorySaveStyle SaveNothing`, or removing the PSReadLine module

> Note: clearing history **after** the fact (`history -c`, deleting the file) is a different technique: T1070.003 Clear Command History, which stays under Stealth.

## Scenario

An attacker who stole an SSH key logs into a Linux web server. Their first command is `unset HISTFILE; export HISTSIZE=0`. Everything they do afterwards (downloading tools, editing crontab) is absent from `.bash_history`.

## Detection challenge

`unset`, `export` and `set` are **shell built-ins**: they do not create a new process, so process-creation logging alone does not see them. Options:

- auditd TTY logging (`pam_tty_audit`) or an EDR that captures interactive shell input
- Detecting the *side effects*: history file replaced by a symlink, zero-size history after an interactive session
- Catching the strings when they appear inside a script or a `bash -c` command line (which is common in automated attack tooling)

## Detections

### D1: History-disabling strings in command lines (scripted use)

```spl
`linux_auditd` type=EXECVE
| eval cmd = coalesce(cmdline, proctitle, _raw)
| where match(cmd, "(?i)(unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0|set\s+\+o\s+history|HISTCONTROL=ignorespace)")
| table _time host auid uid exe cmd
```

If you use EDR telemetry in the `Endpoint.Processes` data model instead:

```spl
| tstats summariesonly=true count min(_time) as first_seen
    from datamodel=Endpoint.Processes
    where Processes.process IN ("*unset HISTFILE*", "*HISTFILE=/dev/null*", "*HISTSIZE=0*", "*set +o history*")
    by Processes.dest Processes.user Processes.process
| `drop_dm_object_name(Processes)`
```

### D2: History file replaced with a link to /dev/null

Requires auditd file watches such as `-w /root/.bash_history -p wa -k histfile` (and for user homes), or `ln` execution logging:

```spl
`linux_auditd` (key="histfile" OR (type=EXECVE (a0="ln" OR exe="*/ln")))
| eval cmd = coalesce(cmdline, proctitle, _raw)
| where match(cmd, "(?i)(\.bash_history|\.zsh_history).*/dev/null|/dev/null.*(\.bash_history|\.zsh_history)") OR key="histfile"
| table _time host auid exe cmd key
```

### D3: PowerShell history saving disabled

```spl
`powershell_operational` EventCode=4104
(ScriptBlockText="*HistorySaveStyle*SaveNothing*" OR ScriptBlockText="*Remove-Module*PSReadLine*")
| table _time host UserID ScriptBlockText
```

## False positives and tuning

- Some admins disable history on purpose when typing secrets. Policy should prefer vaults; repeated use on production servers deserves a conversation.
- Container images and CI jobs often set `HISTSIZE=0`. Exclude build hosts by lookup.

## Triage checklist

- [ ] Interactive session (SSH) or a script? Check the parent process and session.
- [ ] Source IP of the session; is the key/account expected to log in from there?
- [ ] What else happened in that session? Use auditd, process telemetry and network logs, since shell history is no longer available.

## Response

1. Treat the session as suspicious; review all actions via auditd/EDR.
2. Rotate the SSH key or credentials used.
3. Enforce history settings centrally (read-only `HISTFILE` via `/etc/profile.d`, `readonly HISTFILE`) and enable TTY auditing on critical servers.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.003`.

## References

- https://attack.mitre.org/techniques/T1690/
- https://attack.mitre.org/versions/v18/techniques/T1562/003/
