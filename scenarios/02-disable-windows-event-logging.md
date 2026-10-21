# 02 · Disable or Modify Windows Event Logging

| Field | Value |
|---|---|
| Legacy ID | T1562.002 Impair Defenses: Disable Windows Event Logging |
| Current ID | **T1685.001** Disable or Modify Tools: Disable or Modify Windows Event Log |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows |
| Data sources | Security EID 4719, 1100; System EID 7036/7040; Sysmon EID 1 and 13 |
| Suggested severity | High |

## What the adversary does

Instead of deleting logs afterwards, the attacker prevents them from being written in the first place:

- Changing the audit policy so that logon, process creation or object access are no longer audited (`auditpol`)
- Stopping or disabling the Windows Event Log service
- Disabling individual log channels or shrinking them so events roll over quickly
- Modifying registry values under the EventLog service or channel configuration

## Scenario

After obtaining admin rights on a jump server, the attacker disables "Audit Process Creation" and "Audit Logon" with `auditpol`. From then on, lateral movement from this server leaves no 4688 or 4624 events. The only trace is a single **4719** event at the moment of the change.

## Detections

### D1: System audit policy changed (effect-based)

```spl
`wineventlog_security` EventCode=4719
| rex field=Message "Category:\s+(?<audit_category>[^\r\n]+)"
| rex field=Message "Subcategory:\s+(?<audit_subcategory>[^\r\n]+)"
| rex field=Message "Changes:\s+(?<audit_changes>[^\r\n]+)"
| where match(audit_changes, "(?i)removed")
| table _time host SubjectUserName audit_category audit_subcategory audit_changes
```

Focus on changes where Success or Failure auditing was **removed**. Additions are usually hardening.

### D2: Event log service shut down or tampered with

```spl
(`wineventlog_security` EventCode=1100)
OR (`wineventlog_system` EventCode IN (7036, 7040) Message="*Windows Event Log*" (Message="*stopped*" OR Message="*disabled*"))
| eval signal = case(EventCode=1100, "Event logging service shut down",
                     EventCode=7036, "Event Log service stopped",
                     EventCode=7040, "Event Log service start type changed")
| table _time host signal Message
```

EventCode 1100 also appears during normal shutdowns. Join with system shutdown/restart events (System 1074, 6006) and alert only when no shutdown follows within a few minutes.

### D3: Command lines and registry changes that disable logging

```spl
`sysmon` (
  (EventCode=1 (
     (Image="*\\auditpol.exe" (CommandLine="*/set*" CommandLine="*disable*") )
     OR (Image="*\\auditpol.exe" (CommandLine="*/clear*" OR CommandLine="*/remove*"))
     OR (Image="*\\wevtutil.exe" (CommandLine="* sl *" OR CommandLine="*set-log*") (CommandLine="*/e:false*" OR CommandLine="*/enabled:false*" OR CommandLine="*/ms:*"))
     OR ((Image="*\\sc.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*eventlog*" (CommandLine="*stop*" OR CommandLine="*disabled*"))
  ))
  OR (EventCode=13 (
     (TargetObject="*\\Services\\EventLog\\Start" Details="DWORD (0x00000004)")
     OR (TargetObject="*\\WINEVT\\Channels\\*\\Enabled" Details="DWORD (0x00000000)")
  ))
)
| table _time host User EventCode Image CommandLine TargetObject Details
```

## False positives and tuning

- GPO-driven audit policy changes generate 4719 with `SubjectUserName` = the computer account. Compare against the expected GPO baseline; a change that *reduces* auditing should still be reviewed.
- `wevtutil sl /ms:` is used legitimately to **increase** log size. Extract the value and alert only when it is reduced below your baseline.

## Triage checklist

- [ ] Which subcategories were removed? Process Creation, Logon and Security Group Management are the highest-risk ones.
- [ ] Who made the change and from which session (4624 logon type)?
- [ ] Did the host stop sending specific event IDs afterwards? Compare 4688/4624 volume before and after.
- [ ] Is there an approved GPO change?

## Response

1. Restore the audit policy (`gpupdate /force` if the baseline is GPO-enforced), restart the Event Log service.
2. Treat the gap period as "unmonitored": hunt with EDR or network data for that window.
3. Investigate the account; this action requires administrative rights.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.002` (audit policy and Event Log service tests).

## References

- https://attack.mitre.org/techniques/T1685/001/
- https://attack.mitre.org/versions/v18/techniques/T1562/002/
- Event 4719: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719
