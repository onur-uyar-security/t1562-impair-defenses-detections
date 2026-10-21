# 12 · Disable or Modify Network Device Firewall

| Field | Value |
|---|---|
| Legacy ID | T1562.013 Impair Defenses: Disable or Modify Network Device Firewall |
| Current ID | **T1686.002** Disable or Modify System Firewall: Network Device Firewall |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Network devices (routers, firewalls, switches) |
| Data sources | Cisco IOS / ASA syslog, other vendor audit logs, TACACS+ accounting |
| Suggested severity | High |

## What the adversary does

Edge and core network devices are high-value targets: changing their access lists opens paths into the network, and changing their logging blinds the SOC. State-sponsored groups that target edge devices commonly:

- Remove or modify ACL entries to allow their traffic
- Add permit rules for management protocols from external addresses
- Disable or redirect syslog (`no logging host ...`) so changes are not forwarded

## Scenario

An attacker exploits a vulnerability in an internet-facing router, adds an ACL permit for their own IP on SSH, and removes the `logging host` line that sends syslog to the SIEM. From this point the device stops reporting, and the new ACL gives them a durable entry point.

## Detections

### D1: Configuration commands touching ACLs or logging (Cisco IOS)

Requires `archive` → `log config` → `logging enable` on IOS so each configuration command is logged (`%PARSER-5-CFGLOG_LOGGEDCMD`).

```spl
`network_syslog` ("%PARSER-5-CFGLOG_LOGGEDCMD" OR "%SYS-5-CONFIG_I")
| rex "User:(?<admin_user>\S+)\s+logged command:(?<config_command>.+)$"
| rex "Configured from (?<config_source>.+?) by (?<config_user>\S+)"
| eval admin_user = coalesce(admin_user, config_user)
| eval category = case(
    match(config_command, "(?i)^\s*no\s+(ip\s+)?access-list"), "ACL removed",
    match(config_command, "(?i)access-list.*permit"), "ACL permit added",
    match(config_command, "(?i)^\s*no\s+logging"), "Logging disabled",
    match(config_command, "(?i)^\s*no\s+ip\s+access-group"), "ACL unbound from interface",
    isnotnull(config_source), "Config changed",
    true(), null())
| where isnotnull(category)
| table _time host admin_user config_source category config_command
```

### D2: Network device stopped sending syslog

```spl
| tstats latest(_time) as last_seen where `network_syslog_index` earliest=-24h by host
| eval minutes_silent = round((now() - last_seen) / 60)
| lookup asset_inventory.csv host OUTPUT criticality device_role
| where minutes_silent > 30 AND in(device_role, "router", "firewall", "core-switch")
```

## False positives and tuning

- Network team changes during maintenance windows. Correlate with change tickets and TACACS+ accounting; changes from expected admin accounts and jump hosts inside the window can be lower severity.
- Some devices log config changes very differently (Palo Alto, Fortinet, Juniper). Add vendor-specific branches.

## Triage checklist

- [ ] Which account made the change, from which source IP (VTY line)?
- [ ] Is the account a known network admin, and was the change scheduled?
- [ ] Compare the running config with the last known good backup.
- [ ] Any new sessions or traffic matching the new permit?

## Response

1. Restore the configuration from backup; restore syslog forwarding.
2. Rotate device credentials, review AAA configuration.
3. Check firmware integrity against vendor advisories (edge-device compromises often involve firmware or image modification).

## Validation (lab only)

Use a virtual router (e.g. Cisco CML, GNS3) with syslog forwarded to Splunk.

## References

- https://attack.mitre.org/techniques/T1686/002/
- https://attack.mitre.org/versions/v18/techniques/T1562/013/
