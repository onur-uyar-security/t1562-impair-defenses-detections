# Impair Defenses (T1562) → Defense Impairment (TA0112): Detection Scenarios for Splunk

A blue-team detection engineering repository covering the MITRE ATT&CK **Impair Defenses (T1562)** family: how adversaries disable, blind or degrade security controls, and how a SOC can detect it in Splunk.

Each scenario contains a realistic attack narrative, the telemetry that reveals it, ready-to-adapt SPL detections, false-positive tuning notes, a triage checklist and response steps.

> **ATT&CK version note (important)**
> In **ATT&CK v19 (April 2026)** MITRE retired the *Defense Evasion* tactic and split it into **Stealth (TA0005)** and **Defense Impairment (TA0112)**. T1562 was revoked: T1562, T1562.001 and T1562.006 were merged into the new **T1685 Disable or Modify Tools**, and the remaining sub-techniques were reissued under new IDs. **ATT&CK v20 (October 2026)** added **T1685.007 Impair Autonomous Defenses**.
> This repository is organised by the legacy T1562 sub-techniques (because most existing SIEM content, Atomic Red Team tests and vendor rules still use them) and maps every scenario to its **current v19/v20 ID**. See [`mapping/crosswalk.md`](mapping/crosswalk.md).

---

## Why this matters

Impair Defenses is consistently one of the most frequently observed techniques in malware and ransomware campaigns. Attackers rarely stop at "getting in": before encryption or exfiltration they kill the EDR, clear logs, open the firewall or blind the SIEM. If the SOC only watches for the final payload, it detects the attack too late. Detecting the *impairment* step is often the last good chance to stop the intrusion.

A second, less obvious point: some impairment never touches the endpoint. Delaying or cutting the log pipeline (for example with a DDoS against the network segment that carries logs) creates a blind window in which scheduled SIEM rules silently miss events. Scenario [`14`](scenarios/14-coordinated-log-pipeline-blinding.md) covers this.

---

## Coverage matrix

| # | Scenario | Legacy ID (≤ v18) | Current ID (v19/v20) | Main data sources | Detections |
|---|---|---|---|---|---|
| 01 | [Disable or modify security tools (Defender/EDR)](scenarios/01-disable-or-modify-tools.md) | T1562.001 | T1685 | Defender Operational, Sysmon 1/13, System 7036/7040 | 4 |
| 02 | [Disable or modify Windows event logging](scenarios/02-disable-windows-event-logging.md) | T1562.002 | T1685.001 | Security 4719/1100, Sysmon 1/13 | 3 |
| 03 | [Prevent command history logging](scenarios/03-prevent-command-history-logging.md) | T1562.003 | T1690 | auditd, EDR, PowerShell 4104 | 3 |
| 04 | [Disable or modify Windows host firewall](scenarios/04-windows-host-firewall.md) | T1562.004 | T1686 / T1686.003 | Security 4946-4950, Firewall 2004-2006, Sysmon 1 | 3 |
| 05 | [Indicator blocking (ETW, Sysmon, forwarder)](scenarios/05-indicator-blocking.md) | T1562.006 | T1685 | Sysmon 4/16, Sysmon 13, `_internal`, tstats | 4 |
| 06 | [Disable or modify cloud firewall](scenarios/06-cloud-firewall.md) | T1562.007 | T1686.001 | AWS CloudTrail, Azure Activity | 2 |
| 07 | [Disable or modify cloud logs](scenarios/07-cloud-logs.md) | T1562.008 | T1685.002 | AWS CloudTrail, Azure Activity, M365 UAL | 4 |
| 08 | [Safe mode boot](scenarios/08-safe-mode-boot.md) | T1562.009 | T1688 | Sysmon 1/13 | 2 |
| 09 | [Downgrade attack (PowerShell v2, NTLMv1)](scenarios/09-downgrade-attack.md) | T1562.010 | T1689 | PowerShell 400, Security 4624 | 2 |
| 10 | [Modify or spoof security tool UI](scenarios/10-modify-or-spoof-tool-ui.md) | T1562.011 | T1685.003 | Sysmon 13, Defender Operational | 2 |
| 11 | [Disable or modify Linux audit system](scenarios/11-linux-audit-system.md) | T1562.012 | T1685.004 | auditd, syslog, tstats | 3 |
| 12 | [Disable or modify network device firewall](scenarios/12-network-device-firewall.md) | T1562.013 | T1686.002 | Cisco IOS/ASA syslog | 2 |
| 13 | [Clear Windows event logs](scenarios/13-clear-windows-event-logs.md) | T1070.001 | T1685.005 | Security 1102, System 104, Sysmon 1 | 2 |
| 14 | [Coordinated log pipeline blinding (DDoS + intrusion)](scenarios/14-coordinated-log-pipeline-blinding.md) | T1562.006 + T1498 | T1685 + T1498 | tstats, `_internal`, network telemetry | 3 |

Also referenced (no full scenario yet): T1685.006 Clear Linux or Mac System Logs (formerly T1070.002), T1687 Exploitation for Defense Impairment (e.g. BYOVD), T1685.007 Impair Autonomous Defenses (v20).

---

## Repository structure

```
.
├── README.md
├── LICENSE
├── docs/
│   ├── methodology.md            # scenario template, detection design rules, SPL pitfalls
│   └── triage-playbook.md        # generic triage flow for any impairment alert
├── mapping/
│   ├── crosswalk.md              # legacy T1562 → v19/v20 IDs, explained
│   └── attack_t1562_crosswalk.csv
├── scenarios/                    # 14 scenario write-ups with SPL
└── detections/
    └── splunk/
        ├── macros.conf           # index/sourcetype abstraction, adjust once per environment
        ├── savedsearches.conf    # scheduled alerts with throttling and lag-tolerant windows
        └── lookups/
            ├── attack_t1562_crosswalk.csv
            ├── asset_inventory.csv   # sample, replace with your own asset list
            └── security_services.csv
```

---

## How to use

1. **Adapt the macros.** Every query uses macros such as `` `sysmon` `` or `` `wineventlog_security` `` instead of hard-coded indexes. Edit `detections/splunk/macros.conf` once to match your environment.
2. **Upload the lookups.** Settings → Lookups → Lookup table files. `security_services.csv` lists the security services whose stop/disable events are watched.
3. **Run the hunts first.** Before scheduling any detection, run it over 7-30 days of history to see the baseline and tune exclusions.
4. **Schedule.** `savedsearches.conf` shows production-style settings: a 15-minute schedule with a 5-minute lag buffer (`-20m@m` to `-5m@m`), continuous scheduling so skipped runs are caught up, and throttling per host/user.
5. **Validate.** Re-create the behaviour in an isolated lab (for example with Atomic Red Team) and confirm each detection fires.

---

## Lab environment used

- Splunk Enterprise with Splunk Add-on for Microsoft Windows and Splunk Add-on for Sysmon
- Windows 10/11 and Windows Server endpoints with Sysmon (SwiftOnSecurity / Olaf Hartong config) and advanced audit policy
- Ubuntu endpoints with auditd and the Splunk Add-on for Unix and Linux
- AWS CloudTrail and Azure Activity Log samples

Field names in the queries follow the common Splunk TA extractions. If your add-ons extract different field names, adjust them.

---

## Disclaimer

This repository is for defensive and educational purposes. Scenario descriptions explain adversary behaviour at the level needed to build detections; they are not attack tooling. Only reproduce techniques in systems you own or are explicitly authorised to test.

---

## Author

**Osman Onur Uyar**: SOC / Blue Team analyst and ISO/IEC 27001 Lead Auditor, based in Ghent, Belgium. Background of 15+ years in Continuous Improvement and Operational Excellence, which shapes how I approach detection engineering: measure, reduce noise (waste), and improve in short PDCA cycles.

- LinkedIn: www.linkedin.com/in/onur-uyar-security
- Feedback and pull requests are welcome.

## References

- MITRE ATT&CK v19 release: Defense Evasion split and T1562 restructuring (April 2026)
- MITRE ATT&CK v20 release (October 2026)
- MITRE Defense Evasion split crosswalk: https://attack.mitre.org/docs/subtechniques/de-split-crosswalk.csv
- T1685 Disable or Modify Tools: https://attack.mitre.org/techniques/T1685/
- Legacy T1562 (v18): https://attack.mitre.org/versions/v18/techniques/T1562/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
