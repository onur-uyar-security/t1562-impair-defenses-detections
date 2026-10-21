# 14 · Coordinated Log Pipeline Blinding (DDoS + Intrusion)

| Field | Value |
|---|---|
| Related IDs | **T1685** Disable or Modify Tools (legacy T1562.006 Indicator Blocking) + **T1498** Network Denial of Service |
| Tactic | Defense Impairment (TA0112), Impact (TA0040) |
| Platforms | Any environment that ships logs over the network |
| Data sources | `tstats` over all indexes, Splunk `_internal`, `_indextime`, network/NetFlow telemetry |
| Suggested severity | High (context-driven) |

## The idea

Most SIEM detections are **scheduled searches** that look at a fixed time window based on the event's own timestamp (`_time`). If log delivery is delayed, an event can arrive after the window that should have contained it has already been searched. It is then never evaluated by that rule.

An attacker can create this gap deliberately, without touching any security product on the target:

1. A DDoS (or other congestion) is launched against the network segment or link that carries logs to the SIEM.
2. Forwarders on that segment cannot deliver; they queue data locally or, for UDP syslog, simply drop it.
3. In parallel, the real intrusion runs on a system in that segment (or elsewhere, while the SOC is busy with the DDoS).
4. When the network recovers, queued events arrive with old `_time` values. Rules looking at "the last 15 minutes" do not see them.

**Delay vs. loss.** A forwarder with a queue (Splunk UF over TCP, ideally with a persistent queue) only *delays* data: it is still indexed later and can be found by searches over index time. UDP syslog and overflowing queues *lose* data permanently.

## Scenario

A logistics company is hit by a volumetric DDoS against its branch office internet link, which also carries the VPN tunnel to the central Splunk indexers. The SOC treats it as an availability incident. During the 40 minutes of degraded connectivity, an attacker uses previously stolen credentials to log in to a branch file server, creates a local admin account and installs a remote access tool. All events are generated, but they reach Splunk 35-45 minutes late. The 15-minute scheduled rules for "new local admin" and "new service installed" have already run for those time ranges and never see the events.

## Detections

### D1: Ingestion lag per host and sourcetype

```spl
index=* earliest=-30m
| eval lag_sec = _indextime - _time
| stats avg(lag_sec) as avg_lag max(lag_sec) as max_lag count by host sourcetype
| where max_lag > 600
| eval avg_lag_min = round(avg_lag/60, 1), max_lag_min = round(max_lag/60, 1)
| sort - max_lag
```

Running this over all indexes is expensive. In production, restrict to critical indexes, or use the Monitoring Console's data-quality views.

### D2: Many hosts from the same site go silent together

A single silent host is often a laptop going home. Many hosts from one site going silent at once is either a network outage or something worse. Either way, the SOC must know its visibility is reduced.

```spl
| tstats latest(_time) as last_seen where index=* earliest=-4h by host
| lookup asset_inventory.csv host OUTPUT site criticality
| eval silent = if(now() - last_seen > 900, 1, 0)
| stats sum(silent) as silent_hosts count as total_hosts by site
| eval silent_pct = round(silent_hosts / total_hosts * 100, 0)
| where silent_pct >= 30
```

### D3: Catch-up search over index time (retro hunt after recovery)

When D1 or D2 fire and the pipeline recovers, re-run critical detections using **index time** so late events are evaluated. Example for new local admin accounts:

```spl
`wineventlog_security` EventCode IN (4720, 4732) _index_earliest=-2h _index_latest=now earliest=-24h
| table _time _indextime host EventCode TargetUserName SubjectUserName
| eval indexed_at = strftime(_indextime, "%F %T")
```

The `earliest=-24h` bounds the event time generously, while `_index_earliest` selects only what arrived recently.

## Making the scheduled rules themselves resilient

- **Shift windows back** to tolerate normal lag: `dispatch.earliest_time = -20m@m`, `dispatch.latest_time = -5m@m` on a 15-minute schedule.
- **Use index-time windows** for the most critical rules: `_index_earliest=-15m@m _index_latest=@m` with a wide `earliest` on `_time`.
- **Enable continuous scheduling** (`realtime_schedule = 0`) so skipped runs are executed later rather than dropped.
- **Ship logs over TCP/TLS with persistent queues**; avoid UDP syslog for security-relevant sources.
- **Separate the log path** from production traffic where possible (out-of-band management network, QoS priority).

## Analyst mindset

A DDoS should trigger the question "*what else is happening while we are looking at this?*" The incident response playbook for availability incidents should include:

1. Check D1/D2: which sites/hosts are currently under-monitored?
2. Increase EDR-based monitoring of those segments (EDR agents also buffer and report independently).
3. After recovery, run D3-style catch-up searches for the affected period.

## False positives and tuning

- Planned network maintenance and site outages trigger D2. That is acceptable: the purpose is awareness of reduced visibility, not only attack detection.
- D1 thresholds depend on your normal lag. Baseline per sourcetype first; some sources (cloud APIs) are always minutes behind.

## Validation (lab only)

In a lab, block the forwarder's outbound port to the indexer for 30 minutes while generating test events (e.g. create a local user), then remove the block. Confirm that D1 flags the lag, that a normal 15-minute rule misses the events, and that D3 finds them.

## References

- https://attack.mitre.org/techniques/T1685/
- https://attack.mitre.org/techniques/T1498/
- Splunk docs: time modifiers `_index_earliest` / `_index_latest`
- Splunk docs: `savedsearches.conf` (`realtime_schedule`, `dispatch.earliest_time`)
