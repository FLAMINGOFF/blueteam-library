---
title: AWS ECS Task Definition That Queries The Credential Endpoint
summary: |-
  Detects when an Elastic Container Service (ECS) Task Definition includes a command to query the credential endpoint.
  This can indicate a potential adversary adding a backdoor to establish persistence or escalate privileges.
sigma_id: b94bf91e-c2bf-4047-9c43-c6810f43baad
status: test
level: medium
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0003
techniques:
  - T1525
author: Darin Smith
date: '2022-06-07'
modified: '2023-04-24'
falsepositives:
  - Task Definition being modified to request credentials from the Task Metadata Service for valid reasons
references:
  - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ecs__backdoor_task_def/main.py
  - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html
  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_ecs_task_definition_cred_endpoint_query.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS ECS Task Definition That Queries The Credential Endpoint
id: b94bf91e-c2bf-4047-9c43-c6810f43baad
status: test
description: |
    Detects when an Elastic Container Service (ECS) Task Definition includes a command to query the credential endpoint.
    This can indicate a potential adversary adding a backdoor to establish persistence or escalate privileges.
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ecs__backdoor_task_def/main.py
    - https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html
    - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
author: Darin Smith
date: 2022-06-07
modified: 2023-04-24
tags:
    - attack.persistence
    - attack.t1525
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'ecs.amazonaws.com'
        eventName:
            - 'DescribeTaskDefinition'
            - 'RegisterTaskDefinition'
            - 'RunTask'
        requestParameters.containerDefinitions.command|contains: '$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'
    condition: selection
falsepositives:
    - Task Definition being modified to request credentials from the Task Metadata Service for valid reasons
level: medium
```
