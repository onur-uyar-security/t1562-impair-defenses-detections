# 06 · Disable or Modify Cloud Firewall

| Field | Value |
|---|---|
| Legacy ID | T1562.007 Impair Defenses: Disable or Modify Cloud Firewall |
| Current ID | **T1686.001** Disable or Modify System Firewall: Cloud Firewall |
| Tactic | Defense Impairment (TA0112) |
| Platforms | IaaS (AWS, Azure, GCP) |
| Data sources | AWS CloudTrail (`aws:cloudtrail`), Azure Activity Log (`azure:monitor:activity`) |
| Suggested severity | High when a sensitive port is opened to `0.0.0.0/0` |

## What the adversary does

With stolen cloud credentials, the attacker opens network access that the organisation had restricted:

- Adding an ingress rule to an AWS Security Group allowing `0.0.0.0/0` on SSH, RDP or a database port
- Modifying or deleting network ACLs
- Adding an allow rule to an Azure Network Security Group (NSG)

## Scenario

An access key for a CI/CD service account leaks in a public repository. Within hours, an attacker uses it to add `0.0.0.0/0` on TCP 22 to the security group of a database bastion, then logs in with a key they inserted into instance metadata.

## Detections

### D1: AWS security group opened to the internet

```spl
`aws_cloudtrail` eventName IN ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules")
| spath output=cidrs path=requestParameters.ipPermissions.items{}.ipRanges.items{}.cidrIp
| spath output=cidrs6 path=requestParameters.ipPermissions.items{}.ipv6Ranges.items{}.cidrIpv6
| spath output=from_port path=requestParameters.ipPermissions.items{}.fromPort
| spath output=to_port path=requestParameters.ipPermissions.items{}.toPort
| where mvfind(cidrs, "^0\.0\.0\.0/0$") >= 0 OR mvfind(cidrs6, "^::/0$") >= 0
| eval sensitive = if(mvfind(from_port, "^(22|3389|1433|3306|5432|6379|9200|27017)$") >= 0, "yes", "no")
| table _time userIdentity.arn sourceIPAddress awsRegion requestParameters.groupId from_port to_port cidrs sensitive
```

`ModifySecurityGroupRules` uses a different request structure (`securityGroupRuleRequest`). If you see it in your data, add a second `spath` branch for it.

### D2: Network ACL / NSG changes (AWS and Azure)

```spl
(`aws_cloudtrail` eventName IN ("CreateNetworkAclEntry", "ReplaceNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "RevokeSecurityGroupEgress"))
OR (`azure_activity` operationName IN ("MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE"))
| eval actor = coalesce('userIdentity.arn', caller)
| eval action = coalesce(eventName, operationName)
| stats count min(_time) as first_seen values(action) as actions by actor sourceIPAddress
```

Field names differ between Azure add-ons (`operationName` vs `operationName.value`). Adjust to your data.

## False positives and tuning

- Infrastructure-as-code pipelines (Terraform, CloudFormation) make frequent changes. Whitelist their role ARNs, **but** alert if those roles are used from an unusual IP or outside the pipeline's normal schedule.
- Opening port 443 to `0.0.0.0/0` on a load balancer is normal. The `sensitive` flag separates it from SSH/RDP/database exposure.

## Triage checklist

- [ ] Which identity made the change, from which IP and user agent? Console, CLI or SDK?
- [ ] Is the identity normally used from that IP/region?
- [ ] Any new inbound connections in VPC Flow Logs to that port after the change?
- [ ] Other suspicious API calls by the same identity (`CreateAccessKey`, `CreateUser`, `ConsoleLogin` from new country)?

## Response

1. Revoke the rule immediately; consider AWS Config auto-remediation for `0.0.0.0/0` on sensitive ports.
2. Deactivate the access key or session, rotate credentials.
3. Investigate instances behind the group for unauthorised access.

## Validation (lab only)

Use a dedicated sandbox AWS account. Atomic Red Team: `atomics/T1562.007`.

## References

- https://attack.mitre.org/techniques/T1686/001/
- https://attack.mitre.org/versions/v18/techniques/T1562/007/
