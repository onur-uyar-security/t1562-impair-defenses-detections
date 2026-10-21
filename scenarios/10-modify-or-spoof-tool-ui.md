# 10 · Modify or Spoof Security Tool UI

| Field | Value |
|---|---|
| Legacy ID | T1562.011 Impair Defenses: Spoof Security Alerting |
| Current ID | **T1685.003** Disable or Modify Tools: Modify or Spoof Tool UI |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows, macOS, Linux |
| Data sources | Sysmon EID 13; Defender Operational; EDR console health status |
| Suggested severity | Medium |

## What the adversary does

Makes the security product **look** healthy, or hides its warnings, so that users and administrators don't notice it has been disabled:

- Hiding the Windows Security tray icon and suppressing its notifications
- Hiding the Windows Security app pages (Virus & threat protection) through policy
- Displaying fake "protected" status or intercepting the tool's alerts so they never reach the user

This is usually combined with scenario 01: first disable protection, then hide the fact that it is disabled.

## Scenario

On a compromised laptop, the attacker disables Defender real-time protection and then sets the policy values that hide the Windows Security tray icon and disable its notifications. The user never sees the red warning shield.

## Detections

### D1: Policy values that hide Windows Security UI or notifications

```spl
`sysmon` EventCode=13
TargetObject="*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\*"
(
  (TargetObject="*\\Systray\\HideSystray" Details="DWORD (0x00000001)")
  OR (TargetObject="*\\Notifications\\DisableNotifications" Details="DWORD (0x00000001)")
  OR (TargetObject="*\\Notifications\\DisableEnhancedNotifications" Details="DWORD (0x00000001)")
  OR (TargetObject="*\\Virus and threat protection\\UILockdown" Details="DWORD (0x00000001)")
)
| table _time host User Image TargetObject Details
```

### D2: UI hidden shortly after protection was disabled (correlation)

The combination is much stronger than either signal alone.

```spl
(`defender_operational` EventCode IN (5001, 5010, 5012))
OR (`sysmon` EventCode=13 TargetObject="*\\Windows Defender Security Center\\*" Details="DWORD (0x00000001)")
| eval stage = if(like(source, "%Sysmon%") OR like(sourcetype, "%Sysmon%"), "ui_hidden", "protection_disabled")
| stats values(stage) as stages min(_time) as first max(_time) as last by host
| where mvcount(stages)=2 AND (last - first) < 3600
```

### Gap: spoofed status

A fully spoofed UI or intercepted alerts may produce no endpoint event at all. The reliable control is **server-side health**: the EDR/AV management console's view of the agent (last check-in, protection state). Ingest that health data into Splunk and alert when the console reports protection off or the agent stale, regardless of what the endpoint UI shows.

## False positives and tuning

- Kiosk devices and some VDI images hide notifications by GPO. Exclude by asset group; the value should be set by GPO (computer account), not by an interactive user process.

## Triage checklist

- [ ] Was protection also disabled on the host (scenario 01)?
- [ ] Which process wrote the registry value? `reg.exe` or PowerShell from a user session is suspicious; GPO processing is not.
- [ ] What does the central EDR/AV console report for this host?

## Response

1. Restore UI settings via GPO and re-enable protection.
2. Investigate as a scenario 01 incident.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.011` (where available) or set the registry values manually on a lab VM.

## References

- https://attack.mitre.org/techniques/T1685/003/
- https://attack.mitre.org/versions/v18/techniques/T1562/011/
