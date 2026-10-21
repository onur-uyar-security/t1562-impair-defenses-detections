# Methodology

## Scenario template

Every file in `scenarios/` follows the same structure, so analysts can find information in the same place every time:

1. **Header table**: legacy ID, current ID, tactic, platforms, data sources, suggested severity
2. **What the adversary does**: the behaviour in plain language
3. **Scenario**: a short, realistic narrative of where this step sits in an intrusion
4. **Detections**: numbered SPL queries (D1, D2, ...) with the logic explained
5. **False positives and tuning**
6. **Triage checklist**: what the L1 analyst checks first
7. **Response**: containment and recovery actions
8. **Validation**: how to reproduce safely in a lab
9. **References**

## Detection design rules

**1. Detect the impairment, not only the tool.**
Attackers can use many different commands to stop the same service. Wherever possible there is a detection on the *effect* (service stopped, audit policy changed, log channel silent) in addition to detections on specific command lines.

**2. Every "control turned off" event deserves a "control went silent" check.**
If the attacker succeeds in disabling a sensor, the sensor cannot report it. So for every sensor (Sysmon, auditd, forwarder, CloudTrail) there is a heartbeat-style detection based on missing data.

**3. Lag-tolerant windows.**
Scheduled searches look at a window shifted back by a few minutes (for example `earliest=-20m@m latest=-5m@m` on a 15-minute schedule) so that late-arriving events are not missed. For the most critical rules, `_index_earliest` / `_index_latest` can be used to search by index time instead of event time.

**4. Throttle per entity.**
Most detections throttle on `host` and/or `user` for 1 hour, so a single incident produces one alert instead of dozens.

**5. Severity reflects context.**
Disabling Defender on a domain controller is not the same as on a developer VM. Severity in the header is a starting point; asset criticality (via an asset lookup) should raise or lower it.

## SPL pitfalls to remember

- **Boolean precedence:** in Splunk's `search` command, `OR` is evaluated **before** `AND`. A query like `EventCode=1 Image=*sc.exe* OR Image=*net.exe* CommandLine=*stop*` does not mean what it looks like. Every query in this repository wraps OR-groups in explicit parentheses.
- **Backslashes:** in search-time string matching, a Windows path separator is written as `\\`.
- **Field names differ between add-ons.** For example, Sysmon's `Image` may be `process_path` in CIM-normalised data models. Adjust to your environment or use the `Endpoint` data model with `tstats`.
- **Case sensitivity:** search-time term matching is case-insensitive, but `where` and `eval` comparisons are case-sensitive. Use `lower()` in `where` clauses.

## Continuous improvement loop

Detection content is never "finished". Each detection should be reviewed periodically:

| Measure | Question |
|---|---|
| Alert volume | Does it fire too often to be useful? |
| True positive rate | What share of alerts led to a real finding? |
| Mean time to triage | Does the alert give enough context to decide quickly? |
| Coverage | Was the behaviour tested in the lab after the last change? |

This is a PDCA cycle: **Plan** (hypothesis and query), **Do** (deploy), **Check** (metrics above), **Act** (tune, add context, retire).
