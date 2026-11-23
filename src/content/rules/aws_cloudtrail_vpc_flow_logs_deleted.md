---
title: AWS VPC Flow Logs Deleted
summary: |-
  Detects the deletion of one or more VPC Flow Logs in AWS Elastic Compute Cloud (EC2) through the DeleteFlowLogs API call.
  Adversaries may delete flow logs to evade detection or remove evidence of network activity, hindering forensic investigations and visibility into malicious operations.
sigma_id: e386b9b5-af12-450e-afff-761730fb8a98
status: experimental
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0005
techniques: []
author: Ivan Saakov
date: '2025-10-19'
falsepositives:
  - During maintenance operations or testing, authorized administrators may delete VPC Flow Logs as part of routine network management or cleanup activities.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html
  - https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/aws/defense_evasion_ec2_flow_log_deletion
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_cloudtrail_vpc_flow_logs_deleted.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS VPC Flow Logs Deleted
id: e386b9b5-af12-450e-afff-761730fb8a98
status: experimental
description: |
    Detects the deletion of one or more VPC Flow Logs in AWS Elastic Compute Cloud (EC2) through the DeleteFlowLogs API call.
    Adversaries may delete flow logs to evade detection or remove evidence of network activity, hindering forensic investigations and visibility into malicious operations.
references:
    - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html
    - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html
    - https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/aws/defense_evasion_ec2_flow_log_deletion
author: Ivan Saakov
date: 2025-10-19
tags:
    - attack.stealth
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_event_name:
        eventName: 'DeleteFlowLogs'
    selection_status_success:
        errorCode: 'Success'
    selection_status_null:
        errorCode: null
    condition: selection_event_name and 1 of selection_status_*
falsepositives:
    - During maintenance operations or testing, authorized administrators may delete VPC Flow Logs as part of routine network management or cleanup activities.
level: high
```
