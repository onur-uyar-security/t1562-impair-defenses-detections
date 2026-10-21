# 13 · Clear Windows Event Logs

| Field | Value |
|---|---|
| Legacy ID | T1070.001 Indicator Removal: Clear Windows Event Logs |
| Current ID | **T1685.005** Disable or Modify Tools: Clear Windows Event Logs (moved under T1685 in v19) |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows |
| Data sources | Security EID 1102, System EID 104, Sysmon EID 1 |
| Suggested severity | High (Critical on domain controllers) |

## Why it is in this repository

Log clearing was historically part of *Indicator Removal*. In ATT&CK v19 MITRE moved it under T1685 because wiping the Security or System log destroys defensive telemetry as a whole, not just individual traces. It is also one of the most common and reliable impairment signals.

## What the adversary does

Clears one or more event logs after (or during) the intrusion so local forensic evidence disappears: `wevtutil cl Security`, `Clear-EventLog`, `Remove-EventLog`, or via the Event Viewer GUI.

## Scenario

Before leaving a compromised server, the attacker runs a one-liner that clears the Security, System and PowerShell logs. If logs are forwarded to Splunk in near real time, the events are already safe in the SIEM. The clearing itself generates 1102 / 104, which should always alert.

## Detections

### D1: Event log cleared (effect-based)

```spl
(`wineventlog_security` EventCode=1102)
OR (`wineventlog_system` EventCode=104)
| eval cleared_log = if(EventCode=1102, "Security", coalesce(Channel, "System or other channel"))
| rex field=Message "(?i)The (?<log_name>[^\r\n]+?) log file was cleared"
| eval cleared_log = coalesce(log_name, cleared_log)
| rex field=Message "Account Name:\s+(?<cleared_by>[^\r\n]+)"
| table _time host cleared_log cleared_by EventCode
```

### D2: Log clearing commands

```spl
`sysmon` EventCode=1
(
  (Image="*\\wevtutil.exe" (CommandLine="* cl *" OR CommandLine="*clear-log*"))
  OR (CommandLine="*Clear-EventLog*" OR CommandLine="*Remove-EventLog*" OR CommandLine="*Limit-EventLog*")
  OR (CommandLine="*[System.Diagnostics.Eventing.Reader.EventLogSession]*ClearLog*")
)
| table _time host User ParentImage CommandLine
```

A loop that clears **every** channel (`wevtutil el | foreach wevtutil cl`) generates a burst of 104 events. Counting distinct channels cleared per host in a short window catches it:

```spl
`wineventlog_system` EventCode=104
| bin _time span=5m
| stats dc(Channel) as channels_cleared by _time host
| where channels_cleared >= 3
```

## False positives and tuning

- Some admins clear logs when building VM templates or images. These should happen on non-production hosts and by a known account.
- Very few legitimate reasons exist on servers; keep this detection noisy rather than suppressing it.

## Triage checklist

- [ ] Who cleared it? (`SubjectUserName` in 1102)
- [ ] What happened on this host just before the clearing? Search the forwarded copies in Splunk; they survive local clearing.
- [ ] Was the forwarder delayed at that time? If events from the period before clearing are missing in Splunk too, the evidence may be lost (see scenario 14).

## Response

1. Use the SIEM copies to reconstruct the timeline.
2. Treat as active intrusion; investigate the account and isolate the host.
3. Restrict "Manage auditing and security log" rights to a minimal group.

## Validation (lab only)

Atomic Red Team: `atomics/T1070.001` (legacy folder).

## References

- https://attack.mitre.org/techniques/T1685/005/
- https://attack.mitre.org/versions/v18/techniques/T1070/001/
