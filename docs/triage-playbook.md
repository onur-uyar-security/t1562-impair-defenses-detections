# Generic Triage Playbook: Defense Impairment Alerts

Use this flow for any alert in this repository. Scenario files add technique-specific checks.

## 1. Treat it as high priority until proven otherwise

Impairment is usually a **preparation step**. Something else is about to happen (credential dumping, lateral movement, ransomware, exfiltration). Response time matters more than for most alert types.

## 2. Establish who, what, where, when

| Question | Where to look |
|---|---|
| Which account made the change? | `user`, `SubjectUserName`, CloudTrail `userIdentity` |
| From which process / parent? | Sysmon EID 1 `ParentImage`, `ParentCommandLine` |
| On which asset? How critical is it? | asset lookup, CMDB |
| Was it interactive, scripted or remote? | Logon type (4624), parent process (e.g. `wsmprovhost.exe`, `psexesvc.exe`) |
| Is there an approved change ticket? | Change management system |

## 3. Look around the event (±30 minutes)

```spl
index=* host=<HOST> earliest=<T-30m> latest=<T+30m>
| stats count values(EventCode) as event_codes values(sourcetype) as sourcetypes by host user
```

Look for signs of what the impairment was supposed to enable:
- New services or scheduled tasks (7045, 4698)
- Access to LSASS (Sysmon EID 10)
- Remote logons to other hosts from this host/account
- Mass file modifications (ransomware)
- Large outbound transfers

## 4. Check whether telemetry is still flowing

If the alert is about a sensor being disabled, confirm whether the host is still sending data at all:

```spl
| tstats latest(_time) as last_seen where index=* host=<HOST> by sourcetype
| eval minutes_silent = round((now() - last_seen) / 60)
```

A host that went silent right after the alert is a strong signal of a real attack.

## 5. Decide

- **Approved change, matches ticket** → close as benign true positive, consider an exclusion.
- **No explanation, or the account/parent is unusual** → escalate to L2/IR, isolate the host via EDR if possible.
- **Multiple impairment events on several hosts** → likely an active intrusion, start the incident response process.

## 6. Restore the control

Re-enable the disabled control as part of containment, and verify the sensor is reporting again before closing the incident.
