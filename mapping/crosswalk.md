# Crosswalk: Legacy T1562 → ATT&CK v19/v20

Source: MITRE ATT&CK Defense Evasion split crosswalk (v18 → v19), plus the v20 release notes.

## What changed

- **Tactic:** *Defense Evasion (TA0005)* was retired. Its ID now belongs to **Stealth (TA0005)** (blending in so defenses don't notice). A new tactic, **Defense Impairment (TA0112)**, covers breaking or disabling defenses. Every former T1562 behaviour now sits in Defense Impairment.
- **Parent technique:** T1562 *Impair Defenses* was revoked. T1562, T1562.001 and T1562.006 were **merged** into **T1685 Disable or Modify Tools**.
- **Sub-techniques:** the rest were revoked and **reissued** with new IDs, some as sub-techniques of T1685 or of the new **T1686 Disable or Modify System Firewall**, some as standalone techniques.
- **Related moves:** two log-clearing sub-techniques of *Indicator Removal (T1070)* moved under T1685 because they destroy defensive telemetry rather than hide individual traces.
- **New in v19:** T1686.003 Windows Host Firewall, T1687 Exploitation for Defense Impairment.
- **New in v20:** T1685.007 Impair Autonomous Defenses (disrupting AI/LLM-assisted analysis).

## Mapping table

| Legacy ID | Legacy name | Current ID | Current name | Change type |
|---|---|---|---|---|
| T1562 | Impair Defenses | **T1685** | Disable or Modify Tools | Merged into new technique |
| T1562.001 | Disable or Modify Tools | **T1685** | Disable or Modify Tools | Merged into new technique |
| T1562.002 | Disable Windows Event Logging | **T1685.001** | Disable or Modify Tools: Disable or Modify Windows Event Log | Revoked and reissued |
| T1562.003 | Impair Command History Logging | **T1690** | Prevent Command History Logging | Revoked and reissued |
| T1562.004 | Disable or Modify System Firewall | **T1686** | Disable or Modify System Firewall | Revoked and reissued |
| T1562.006 | Indicator Blocking | **T1685** | Disable or Modify Tools | Merged into new technique |
| T1562.007 | Disable or Modify Cloud Firewall | **T1686.001** | Disable or Modify System Firewall: Cloud Firewall | Revoked and reissued |
| T1562.008 | Disable or Modify Cloud Logs | **T1685.002** | Disable or Modify Tools: Disable or Modify Cloud Log | Revoked and reissued |
| T1562.009 | Safe Mode Boot | **T1688** | Safe Mode Boot | Revoked and reissued |
| T1562.010 | Downgrade Attack | **T1689** | Downgrade Attack | Revoked and reissued |
| T1562.011 | Spoof Security Alerting | **T1685.003** | Disable or Modify Tools: Modify or Spoof Tool UI | Revoked and reissued |
| T1562.012 | Disable or Modify Linux Audit System | **T1685.004** | Disable or Modify Tools: Disable or Modify Linux Audit System Log | Revoked and reissued |
| T1562.013 | Disable or Modify Network Device Firewall | **T1686.002** | Disable or Modify System Firewall: Network Device Firewall | Revoked and reissued |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | **T1685.005** | Disable or Modify Tools: Clear Windows Event Logs | Revoked and reissued |
| T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | **T1685.006** | Disable or Modify Tools: Clear Linux or Mac System Logs | Revoked and reissued |
| (new, v19) | – | **T1686.003** | Disable or Modify System Firewall: Windows Host Firewall | New sub-technique |
| (new, v19) | – | **T1687** | Exploitation for Defense Impairment | New technique |
| (new, v20) | – | **T1685.007** | Disable or Modify Tools: Impair Autonomous Defenses | New sub-technique |

> T1562.005 was deprecated before v19 and is not part of this mapping.

## Practical impact for a SOC

1. **Re-tag detections.** Any correlation search, notable/finding or risk rule annotated with `T1562.*` should carry the new ID. Keeping both IDs during the transition helps reporting continuity.
2. **Update dashboards.** MITRE coverage dashboards that group by tactic will show a "missing" Defense Evasion column and a new Defense Impairment column.
3. **Check tool content.** Atomic Red Team tests, Sigma rules and vendor content may still use legacy IDs for some time. The CSV in this folder can be used as a Splunk lookup to translate on the fly:

```spl
| inputlookup attack_t1562_crosswalk.csv
| table legacy_id current_id current_name current_tactic
```

```spl
`notable`
| lookup attack_t1562_crosswalk.csv legacy_id AS annotations.mitre_attack OUTPUT current_id current_name
| stats count by rule_name annotations.mitre_attack current_id current_name
```
