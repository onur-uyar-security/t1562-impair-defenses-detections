# 07 · Disable or Modify Cloud Logs

| Field | Value |
|---|---|
| Legacy ID | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| Current ID | **T1685.002** Disable or Modify Tools: Disable or Modify Cloud Log |
| Tactic | Defense Impairment (TA0112) |
| Platforms | IaaS, SaaS (Microsoft 365 / Entra ID) |
| Data sources | AWS CloudTrail, Azure Activity Log, Microsoft 365 Unified Audit Log (`o365:management:activity`) |
| Suggested severity | Critical |

## What the adversary does

Turns off the cloud equivalent of the security camera:

- AWS: `StopLogging`, `DeleteTrail`, `UpdateTrail` (e.g. removing multi-region), `PutEventSelectors` (excluding management or data events), deleting VPC Flow Logs, disabling GuardDuty
- Azure: deleting diagnostic settings that forward activity or resource logs to the SIEM
- Microsoft 365: disabling unified audit log ingestion, or reducing mailbox auditing

## Scenario

An attacker with an over-privileged IAM role disables the organisation's CloudTrail trail in one region, then creates new access keys and spins up instances in that region for crypto-mining. Because CloudTrail logs its own `StopLogging` call before stopping, that single event is the SOC's last signal.

## Detections

### D1: AWS logging stopped or weakened

```spl
`aws_cloudtrail` eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
                               "DeleteFlowLogs", "DeleteDetector", "UpdateDetector",
                               "DeleteConfigurationRecorder", "StopConfigurationRecorder")
| eval risk = case(
    in(eventName, "StopLogging", "DeleteTrail", "DeleteDetector", "StopConfigurationRecorder"), "critical",
    true(), "high")
| table _time eventName risk userIdentity.arn sourceIPAddress userAgent awsRegion requestParameters.name errorCode
```

Note `errorCode`: a failed attempt (`AccessDenied`) is still an attempt worth investigating.

### D2: Azure diagnostic settings deleted

```spl
`azure_activity` operationName IN ("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
                                   "MICROSOFT.AADIAM/DIAGNOSTICSETTINGS/DELETE")
| table _time caller callerIpAddress operationName resourceId status
```

### D3: Microsoft 365 audit logging disabled

```spl
`o365_management` Operation IN ("Set-AdminAuditLogConfig", "Set-MailboxAuditBypassAssociation", "Set-Mailbox", "Set-OrganizationConfig")
| eval params = mvjoin('Parameters{}.Name', ",") . " = " . mvjoin('Parameters{}.Value', ",")
| where match(params, "(?i)(UnifiedAuditLogIngestionEnabled.*False|AuditBypassEnabled.*True|AuditEnabled.*False|AuditDisabled.*True)")
| table _time UserId ClientIP Operation ObjectId params
```

### D4 (supporting): CloudTrail data stopped arriving

```spl
| tstats latest(_time) as last_seen where `aws_cloudtrail_index` by sourcetype
| eval minutes_silent = round((now() - last_seen) / 60)
| where minutes_silent > 60
```

## False positives and tuning

- Trail reconfiguration during platform migrations. Require a change ticket; these events are rare enough that every one deserves review.
- `UpdateTrail` and `PutEventSelectors` can also **add** coverage. Compare old and new configuration in the request parameters before closing.

## Triage checklist

- [ ] Which identity, from where, with which user agent?
- [ ] Is logging now off? Check the trail status directly in the console.
- [ ] What did the same identity do **before** and immediately after (from other log sources still running: GuardDuty, VPC Flow Logs, billing anomalies)?

## Response

1. Re-enable logging immediately; consider an SCP (Service Control Policy) that denies `StopLogging`/`DeleteTrail` for everyone except a break-glass role.
2. Disable the identity's keys and sessions.
3. Treat the period with logging off as a gap: review billing, resource inventory and other telemetry for that time.

## Validation (lab only)

Use a sandbox account. Atomic Red Team: `atomics/T1562.008`.

## References

- https://attack.mitre.org/techniques/T1685/002/
- https://attack.mitre.org/versions/v18/techniques/T1562/008/
