# 05 · Indicator Blocking (ETW, Sysmon, Log Forwarder)

| Field | Value |
|---|---|
| Legacy ID | T1562.006 Impair Defenses: Indicator Blocking |
| Current ID | **T1685** Disable or Modify Tools (merged in v19) |
| Tactic | Defense Impairment (TA0112) |
| Platforms | Windows, Linux, macOS |
| Data sources | Sysmon EID 4, 16, 13; Sysmon EID 1; Splunk `_internal`; `tstats` over all indexes |
| Suggested severity | High |

## What the adversary does

Blocks telemetry **on its way** from the sensor to the SIEM, so the security product looks healthy but nothing reaches the analysts:

- Disabling Event Tracing for Windows (ETW) providers or autologger sessions that EDR and Sysmon depend on
- Stopping Sysmon or replacing its configuration with an empty one
- Stopping, reconfiguring or blocking the log forwarder (Splunk Universal Forwarder, Winlogbeat, rsyslog)
- Adding hosts-file or firewall entries that stop the forwarder reaching the indexer

## Scenario

The attacker knows the organisation forwards logs with the Splunk Universal Forwarder. They add an outbound firewall block for the indexer's port 9997 on the compromised host. The forwarder keeps running, queues data locally, and the host simply disappears from Splunk. Detections that look for specific malicious events will never fire, because there are no events.

## Detections

### D1: Sysmon stopped or its configuration changed

```spl
`sysmon` EventCode IN (4, 16)
| eval signal = case(
    EventCode=4 AND match(_raw, "(?i)<Data Name='State'>Stopped"), "Sysmon service stopped",
    EventCode=16, "Sysmon configuration changed",
    true(), "Sysmon state change")
| where signal!="Sysmon state change"
| table _time host signal _raw
```

Sysmon EID 16 also fires on legitimate config deployments. Compare the `ConfigurationFileHash` with your approved hash list (a lookup).

### D2: ETW autologger or provider disabled

```spl
`sysmon` (
  (EventCode=13 TargetObject="*\\Control\\WMI\\Autologger\\*" (TargetObject="*\\Enabled" OR TargetObject="*\\Start") Details="DWORD (0x00000000)")
  OR (EventCode=1 Image="*\\logman.exe" (CommandLine="*stop*" OR CommandLine="*delete*" OR (CommandLine="*update*" CommandLine="*--p*")))
)
| table _time host User EventCode Image CommandLine TargetObject Details
```

### D3: Splunk forwarder stopped or reconfigured on the endpoint

```spl
`sysmon` EventCode=1
(
  (CommandLine="*splunkd*" OR CommandLine="*SplunkForwarder*" OR CommandLine="*splunk.exe*")
  (CommandLine="*stop*" OR CommandLine="*disable*" OR CommandLine="*remove*" OR CommandLine="*delete*")
)
| table _time host User ParentImage Image CommandLine
```

### D4: Host went silent (the detection that still works when everything else is blinded)

This is a missing-data detection. It compares each host's normal reporting with its latest event.

```spl
| tstats latest(_time) as last_seen count where index=* earliest=-24h by host
| eval minutes_silent = round((now() - last_seen) / 60)
| lookup asset_inventory.csv host OUTPUT criticality expected_reporting
| where minutes_silent > 30 AND in(criticality, "high", "critical")
| sort - minutes_silent
| table host criticality last_seen minutes_silent count
```

For forwarder health directly:

```spl
index=_internal sourcetype=splunkd group=tcpin_connections earliest=-24h
| stats latest(_time) as last_connect by hostname
| eval minutes_since = round((now() - last_connect) / 60)
| where minutes_since > 30
```

## False positives and tuning

- Laptops go offline every evening. Use an asset lookup and apply D4 to always-on servers and critical assets, or use a longer threshold for end-user devices.
- Planned maintenance windows: suppress via a maintenance lookup.

## Triage checklist

- [ ] Did the host go silent **right after** another suspicious event? That combination is a strong signal.
- [ ] Is the host still reachable on the network (ping, EDR console, NetFlow)? Online but silent = suspicious.
- [ ] Are other sensors on the host (EDR, network) still seeing it?

## Response

1. Reach the host through a different channel (EDR console) and check service and firewall status.
2. When the forwarder reconnects, queued data will arrive late: re-run critical detections over the gap using index time (`_index_earliest`).
3. If the host stays unreachable but on the network, isolate it at the switch or firewall.

## Validation (lab only)

Atomic Red Team: `atomics/T1562.006` and `atomics/T1562.001` (Sysmon-related tests). For D4, stop the forwarder on a lab VM and confirm the alert after the threshold.

## References

- https://attack.mitre.org/techniques/T1685/
- https://attack.mitre.org/versions/v18/techniques/T1562/006/
- Sysmon event reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
