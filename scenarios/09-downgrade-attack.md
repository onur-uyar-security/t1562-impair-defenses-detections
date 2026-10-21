# 09 · Downgrade Attack (PowerShell v2, NTLMv1)

| Field | Value |
|---|---|
| Legacy ID | T1562.010 Impair Defenses: Downgrade Attack |
| Current ID | **T1689** Downgrade Attack |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows, Linux, network |
| Data sources | Windows PowerShell EID 400; Sysmon EID 1; Security EID 4624 |
| Suggested severity | Medium (High in combination with other activity) |

## What the adversary does

Forces the use of an older, weaker version of a feature that lacks modern security controls:

- **PowerShell v2:** has no Script Block Logging, no AMSI, no Constrained Language Mode. Running `powershell -version 2` bypasses most PowerShell visibility, if the .NET 2.0 / PowerShell v2 engine is still installed.
- **NTLMv1 / LM:** weak authentication that can be cracked or relayed easily.
- **Protocol downgrades** such as forcing SMBv1 or older TLS versions.

## Scenario

An attacker's script starts with `powershell.exe -Version 2 -NoProfile ...`. On a host where the PowerShell v2 feature was never removed, the script runs without generating any 4104 script block events. The only trace is the engine start event showing version 2.0.

## Detections

### D1: PowerShell engine started with version 2

```spl
`powershell_classic` EventCode=400
| rex field=Message "EngineVersion=(?<engine_version>[\d\.]+)"
| rex field=Message "HostApplication=(?<host_application>[^\r\n]+)"
| where like(engine_version, "2.%")
| table _time host engine_version host_application
```

Supplement with command-line detection:

```spl
`sysmon` EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where match(CommandLine, "(?i)\s-(v|ve|ver|vers|versi|versio|version)\s+2(\.0)?(\s|$)")
| table _time host User ParentImage CommandLine
```

The regex covers abbreviated forms like `-v 2` and `-ver 2`.

### D2: NTLMv1 / LM authentication in use

```spl
`wineventlog_security` EventCode=4624
| rex field=Message "Package Name \(NTLM only\):\s+(?<ntlm_package>[^\r\n]+)"
| where match(ntlm_package, "(?i)(NTLM V1|LM)")
| stats count min(_time) as first_seen max(_time) as last_seen values(IpAddress) as src_ips by host TargetUserName ntlm_package
```

If NTLMv1 is used by legacy systems in your environment, this becomes a hardening finding first and a detection second: build the list of legacy sources, then alert on anything outside it.

## False positives and tuning

- Some old management scripts or vendor tools still call `-version 2`. The real fix is removing the PowerShell v2 feature (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`); once removed, any attempt is a strong signal.
- NTLMv1 from known legacy appliances: maintain a lookup of approved sources.

## Triage checklist

- [ ] What launched PowerShell v2 (parent process)? Office, browser or `wmiprvse.exe` parents are suspicious.
- [ ] What was the full command line? Encoded commands (`-enc`) with v2 are a red flag.
- [ ] For NTLMv1: which source IP, which account? Is it a known legacy system?

## Response

1. Remove PowerShell v2 from all supported endpoints.
2. Enforce NTLMv2 only (`LmCompatibilityLevel` = 5) once legacy dependencies are resolved.
3. Investigate the process tree that triggered the downgrade.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.010`.

## References

- https://attack.mitre.org/techniques/T1689/
- https://attack.mitre.org/versions/v18/techniques/T1562/010/
