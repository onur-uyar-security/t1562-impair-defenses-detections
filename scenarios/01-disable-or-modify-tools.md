# 01 · Disable or Modify Security Tools (Defender / EDR)

| Field | Value |
|---|---|
| Legacy ID | T1562.001 Impair Defenses: Disable or Modify Tools |
| Current ID | **T1685** Disable or Modify Tools |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows (also Linux/macOS with other telemetry) |
| Data sources | Microsoft-Windows-Windows Defender/Operational, Sysmon EID 1 and 13, System EID 7036/7040 |
| Suggested severity | High (Critical on servers and domain controllers) |

## What the adversary does

Stops, uninstalls or reconfigures endpoint protection so the next stages of the attack run unnoticed. Common variants:

- Turning off Microsoft Defender real-time protection or adding broad exclusions (a whole drive, `C:\Users\Public`, a staging folder)
- Stopping or disabling security services (Defender, EDR sensor, Sysmon)
- Killing security processes or unloading their file-system minifilter drivers
- Setting Defender policy registry keys that disable protection

## Scenario

A ransomware affiliate gains access through a compromised VPN account and moves to a file server with domain admin credentials. Before deploying the encryptor, they run a short PowerShell script that adds `C:\ProgramData` to the Defender exclusion list and disables real-time monitoring. The encryptor is then dropped into `C:\ProgramData` where it is no longer scanned.

The SOC's chance: the exclusion and the protection change both generate events **minutes before** encryption starts.

## Detections

### D1: Defender protection disabled or exclusions changed (effect-based)

Defender reports its own state changes. This works regardless of which command or tool caused them.

```spl
`defender_operational` EventCode IN (5001, 5010, 5012, 5007)
| eval change = case(
    EventCode=5001, "Real-time protection disabled",
    EventCode=5010, "Antispyware scanning disabled",
    EventCode=5012, "Antivirus scanning disabled",
    EventCode=5007, "Configuration changed")
| where EventCode!=5007
    OR match(_raw, "(?i)(Exclusions\\\\(Paths|Extensions|Processes)|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring)")
| table _time host change EventCode _raw
```

EventCode 5007 fires for every configuration change, including signature updates of settings, so it is filtered down to exclusions and "Disable*" values.

### D2: Command lines that disable Defender or stop security services

```spl
`sysmon` EventCode=1
(
  (CommandLine="*Set-MpPreference*" (CommandLine="*-Disable*" OR CommandLine="*-Exclusion*"))
  OR (CommandLine="*Add-MpPreference*" CommandLine="*-Exclusion*")
  OR ((Image="*\\sc.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe")
      (CommandLine="*stop*" OR CommandLine="*delete*" OR CommandLine="*disabled*")
      (CommandLine="*WinDefend*" OR CommandLine="*Sense*" OR CommandLine="*Sysmon*" OR CommandLine="*WdNisSvc*"))
  OR (Image="*\\fltMC.exe" CommandLine="*unload*")
  OR (Image="*\\taskkill.exe" (CommandLine="*MsMpEng*" OR CommandLine="*MsSense*" OR CommandLine="*Sysmon*"))
)
| table _time host User ParentImage Image CommandLine
```

Note the explicit parentheses: in Splunk, `OR` binds before `AND`.

### D3: Defender policy registry keys set to disable protection

```spl
`sysmon` EventCode=13
TargetObject="*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender*"
(TargetObject="*\\DisableAntiSpyware" OR TargetObject="*\\DisableRealtimeMonitoring"
 OR TargetObject="*\\DisableBehaviorMonitoring" OR TargetObject="*\\DisableIOAVProtection"
 OR TargetObject="*\\DisableScriptScanning")
Details="DWORD (0x00000001)"
| table _time host User Image TargetObject Details
```

### D4: Security service stopped or start type changed to disabled (lookup-driven)

Uses `security_services.csv` so new products can be added without editing the query.

```spl
`wineventlog_system` EventCode IN (7036, 7040)
| rex field=Message "The (?<service_display>.+?) service (entered the (?<new_state>\w+) state|start type was changed from (?<old_start>.+?) to (?<new_start>.+?)\.)"
| lookup security_services.csv service_display OUTPUT product criticality
| where isnotnull(product) AND (new_state="stopped" OR new_start="disabled")
| table _time host service_display product criticality new_state new_start
```

## False positives and tuning

- Installing a third-party AV puts Defender into passive mode, which generates 5001/5010. Correlate with software deployment tickets.
- Admins adding exclusions for backup, database or build folders. Exclusions **themselves** are risky; maintain an approved-exclusions lookup rather than ignoring D1.
- Service restarts during patching (7036 "stopped" followed by "running" within minutes). Add a check that the service did not come back:

```spl
... | stats earliest(_time) as first latest(new_state) as final_state by host service_display
    | where final_state="stopped"
```

## Triage checklist

- [ ] Which account and parent process made the change? Is it a deployment tool (SCCM, Intune) or an interactive shell?
- [ ] For exclusions: which path? Is anything executable present in it now?
- [ ] Any new executables, services (7045) or scheduled tasks (4698) on the host in the following 30 minutes?
- [ ] Is Tamper Protection enabled? Did Defender log 5013 (tamper blocked)? A blocked attempt is still a strong signal.
- [ ] Same change on other hosts at the same time (scripted, domain-wide)?

## Response

1. Isolate the host via EDR if the change is unexplained.
2. Re-enable protection, remove unapproved exclusions, run a full scan of the excluded path.
3. Reset credentials of the account used, review its other logons.
4. Enable Tamper Protection and restrict who can change Defender policy.

## Validation (lab only)

Atomic Red Team tests are indexed under the legacy folder `atomics/T1562.001`. Run the Defender-disable and exclusion tests on a lab VM and confirm D1-D3 fire.

## References

- https://attack.mitre.org/techniques/T1685/
- https://attack.mitre.org/versions/v18/techniques/T1562/001/
- Microsoft Defender Antivirus event IDs: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
