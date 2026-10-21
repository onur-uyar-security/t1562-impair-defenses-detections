# 08 · Safe Mode Boot

| Field | Value |
|---|---|
| Legacy ID | T1562.009 Impair Defenses: Safe Mode Boot |
| Current ID | **T1688** Safe Mode Boot |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows |
| Data sources | Sysmon EID 1, 12, 13; System EID 1074 (restart) |
| Suggested severity | Critical |

## What the adversary does

Windows Safe Mode loads only a minimal set of drivers and services. Most EDR and antivirus products do **not** run there. Ransomware families have used this by:

1. Registering their own service or binary to start in Safe Mode (under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal` or `\Network`)
2. Setting the boot configuration to Safe Mode with `bcdedit /set {default} safeboot minimal` (or `network`)
3. Forcing a restart, then encrypting while protections are offline

## Scenario

After gaining domain admin, the attacker pushes a script to file servers that registers the encryptor as a Safe Mode service, sets `safeboot network` and reboots. The servers come back in Safe Mode with networking, the EDR sensor is not running, and encryption begins.

## Detections

### D1: Boot configuration set to Safe Mode

```spl
`sysmon` EventCode=1
(
  (Image="*\\bcdedit.exe" CommandLine="*safeboot*")
  OR (Image="*\\bcdedit.exe" CommandLine="*bootstatuspolicy*ignoreallfailures*")
  OR (Image="*\\bcdedit.exe" CommandLine="*recoveryenabled*no*")
)
| table _time host User ParentImage CommandLine
```

The second and third patterns (disabling recovery) are also typical ransomware preparation.

### D2: Service or value registered under SafeBoot keys

```spl
`sysmon` EventCode IN (12, 13)
(TargetObject="*\\Control\\SafeBoot\\Minimal\\*" OR TargetObject="*\\Control\\SafeBoot\\Network\\*")
| where NOT match(Image, "(?i)\\\\(TrustedInstaller|msiexec|services)\.exe$")
| table _time host User EventCode Image TargetObject Details
```

Correlate D1 and D2 with a restart (System 1074) on the same host within an hour for a very high-confidence alert:

```spl
(`sysmon` EventCode=1 Image="*\\bcdedit.exe" CommandLine="*safeboot*")
OR (`wineventlog_system` EventCode=1074)
| eval stage = if(EventCode=1074, "restart", "safeboot_set")
| stats values(stage) as stages min(_time) as first max(_time) as last by host
| where mvcount(stages)=2 AND (last - first) < 3600
```

## False positives and tuning

- IT support occasionally uses Safe Mode for troubleshooting, usually interactively on a single workstation. Scripted, server-side or multi-host changes are highly suspicious.
- Some security products legitimately register Safe Mode entries during installation; the exclusion for installer processes covers most.

## Triage checklist

- [ ] Server or workstation? How many hosts?
- [ ] Has the host already restarted? If yes, assume encryption may be in progress.
- [ ] Which service/binary was registered for Safe Mode?

## Response

1. **Act immediately:** isolate the host before the reboot if possible.
2. Remove the `safeboot` setting (`bcdedit /deletevalue {default} safeboot`) and the registry entries.
3. Hunt for the same commands across the estate; this is often part of a mass deployment.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.009`. Use a snapshot VM; the test changes the boot configuration.

## References

- https://attack.mitre.org/techniques/T1688/
- https://attack.mitre.org/versions/v18/techniques/T1562/009/
