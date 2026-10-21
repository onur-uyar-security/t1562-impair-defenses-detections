# 11 · Disable or Modify Linux Audit System

| Field | Value |
|---|---|
| Legacy ID | T1562.012 Impair Defenses: Disable or Modify Linux Audit System |
| Current ID | **T1685.004** Disable or Modify Tools: Disable or Modify Linux Audit System Log |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Linux |
| Data sources | auditd (`CONFIG_CHANGE`, `DAEMON_END`, `EXECVE`), syslog/journald, `tstats` |
| Suggested severity | High |

## What the adversary does

The Linux audit framework (`auditd`) is often the main source of process and file-access telemetry on servers. Attackers with root:

- Disable auditing at kernel level: `auditctl -e 0`
- Delete all audit rules: `auditctl -D`
- Stop or mask the service: `systemctl stop auditd`, `systemctl mask auditd`
- Edit `/etc/audit/audit.rules` or `/etc/audit/rules.d/*` to remove watches
- Fill the disk or change `auditd.conf` so logs are dropped

## Scenario

An attacker who exploited a web application on a Linux server escalates to root and runs `auditctl -D` followed by `auditctl -e 0`. The kernel logs one `CONFIG_CHANGE` record for each command, then auditing stops. Their following actions (installing a backdoor, adding an SSH key) produce no audit records.

## Detections

### D1: Audit configuration changed by auditctl or rules removed

```spl
`linux_auditd` type=CONFIG_CHANGE
| eval change = case(
    match(_raw, "audit_enabled=0"), "Auditing disabled",
    match(_raw, "op=\"?remove_rule"), "Audit rule removed",
    true(), "Other config change")
| where change!="Other config change"
| stats count min(_time) as first_seen values(change) as changes by host auid
```

### D2: auditd stopped or masked / auditctl used destructively

```spl
(`linux_auditd` type=DAEMON_END)
OR (`linux_auditd` type=EXECVE
    ((a0="auditctl" ((a1="-e" a2="0") OR a1="-D"))
     OR (a0="systemctl" (a1="stop" OR a1="disable" OR a1="mask") (a2="auditd" OR a2="auditd.service"))
     OR (a0="service" a1="auditd" a2="stop")))
| eval signal = if(type="DAEMON_END", "auditd daemon ended", "Destructive audit command")
| table _time host auid type signal a0 a1 a2
```

Argument fields (`a0`, `a1`, ...) are extracted by the Splunk Add-on for Unix and Linux. If you use `proctitle` or `cmdline` instead, match on that field.

### D3: Audit data stopped arriving from a server

```spl
| tstats latest(_time) as last_seen where `linux_auditd_index` sourcetype="linux:audit" earliest=-24h by host
| eval minutes_silent = round((now() - last_seen) / 60)
| lookup asset_inventory.csv host OUTPUT criticality
| where minutes_silent > 20 AND in(criticality, "high", "critical")
```

Busy servers produce audit events every minute. Silence after a `CONFIG_CHANGE` is a strong signal.

## False positives and tuning

- Configuration management (Ansible, Puppet) reloads rules with `auditctl -R` or `augenrules --load`, which can produce rule remove/add pairs. Exclude the automation's `auid` and expected time windows; `audit_enabled=0` should almost never be legitimate.
- Planned reboots produce `DAEMON_END`. Correlate with system shutdown records.

## Triage checklist

- [ ] Which `auid` (the original login UID, not just root) performed the change?
- [ ] How did that user become root (`sudo`, `su`, exploited service)?
- [ ] Is auditd running now? Do the rules match the baseline (`auditctl -l`)?
- [ ] What happened on the host between the change and now (EDR, network logs, file integrity monitoring)?

## Response

1. Restore rules and set the audit configuration to immutable (`-e 2` at the end of the rules file) so changes require a reboot.
2. Investigate the gap period with other telemetry.
3. Contain the host and the account.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.012`.

## References

- https://attack.mitre.org/techniques/T1685/004/
- https://attack.mitre.org/versions/v18/techniques/T1562/012/
- `auditctl(8)` manual page
