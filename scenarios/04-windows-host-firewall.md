# 04 · Disable or Modify Windows Host Firewall

| Field | Value |
|---|---|
| Legacy ID | T1562.004 Impair Defenses: Disable or Modify System Firewall |
| Current ID | **T1686** Disable or Modify System Firewall; Windows-specific: **T1686.003** Windows Host Firewall (new in v19) |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows (Linux/macOS: iptables, nftables, ufw, pf) |
| Data sources | Security EID 4946, 4947, 4948, 4950; Microsoft-Windows-Windows Firewall With Advanced Security/Firewall EID 2004, 2005, 2006; Sysmon EID 1 |
| Suggested severity | Medium (High if inbound RDP/SMB opened or the firewall turned off) |

## What the adversary does

- Turns the firewall off for one or all profiles
- Adds an allow rule for inbound RDP (3389), SMB (445), WinRM (5985/5986) or a C2 port
- Deletes block rules that segment the network

## Scenario

After compromising a workstation, the attacker adds an inbound allow rule for TCP 3389 named "Remote Desktop - Update" so it blends in with built-in rules, and enables RDP. They now have a stable interactive path that does not depend on the original malware.

## Detections

### D1: Firewall disabled or rule added/modified/deleted (effect-based)

```spl
(`wineventlog_security` EventCode IN (4946, 4947, 4948, 4950))
OR (`windows_firewall` EventCode IN (2004, 2005, 2006, 2003))
| eval action = case(
    in(EventCode, "4946", "2004"), "Rule added",
    in(EventCode, "4947", "2005"), "Rule modified",
    in(EventCode, "4948", "2006"), "Rule deleted",
    in(EventCode, "4950", "2003"), "Firewall setting changed")
| rex field=Message "Rule Name:\s+(?<rule_name>[^\r\n]+)"
| table _time host action EventCode rule_name Message
```

On newer Windows builds the Firewall channel may use additional event IDs (e.g. 2097-2099). Check your own baseline.

### D2: Command lines that disable the firewall or open risky ports

```spl
`sysmon` EventCode=1
(
  (Image="*\\netsh.exe" CommandLine="*firewall*" (CommandLine="*state off*" OR CommandLine="*opmode disable*"))
  OR (Image="*\\netsh.exe" CommandLine="*firewall*" CommandLine="*add*rule*" CommandLine="*action=allow*" CommandLine="*dir=in*")
  OR (CommandLine="*Set-NetFirewallProfile*" CommandLine="*-Enabled*False*")
  OR (CommandLine="*New-NetFirewallRule*" CommandLine="*-Direction*Inbound*" CommandLine="*-Action*Allow*")
)
| rex field=CommandLine "(?i)(localport=|-LocalPort\s+)(?<local_port>[\d,]+)"
| eval risky_port = if(match(local_port, "(^|,)(3389|445|5985|5986|22|135)(,|$)"), "yes", "no")
| table _time host User ParentImage CommandLine local_port risky_port
```

### D3: Firewall turned off via registry

```spl
`sysmon` EventCode=13
TargetObject="*\\SharedAccess\\Parameters\\FirewallPolicy\\*Profile\\EnableFirewall"
Details="DWORD (0x00000000)"
| table _time host User Image TargetObject Details
```

## False positives and tuning

- Software installers routinely add allow rules for their own executables (Teams, Zoom, game launchers). Inbound rules for **specific ports** from non-installer parents are more interesting than application rules.
- GPO-pushed rules show up as many simultaneous changes across hosts with the system account. Baseline by `rule_name`.

## Triage checklist

- [ ] Which profile was changed (Domain/Private/Public)? Disabling the Public profile on a laptop is high risk.
- [ ] Which port/program does the new rule allow? Is the rule name imitating a built-in one?
- [ ] Any inbound connections to that port after the change (firewall/NetFlow/Sysmon EID 3)?
- [ ] Was RDP also enabled (`fDenyTSConnections` set to 0)?

## Response

1. Remove the rule or re-enable the profile; enforce firewall settings by GPO so local changes are overwritten.
2. Review inbound connections during the exposure window.
3. Investigate the account that made the change.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.004`.

## References

- https://attack.mitre.org/techniques/T1686/
- https://attack.mitre.org/techniques/T1686/003/
- https://attack.mitre.org/versions/v18/techniques/T1562/004/
