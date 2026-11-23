---
title: Potential Linux Amazon SSM Agent Hijacking
summary: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
sigma_id: f9b3edc5-3322-4fc7-8aa3-245d646cc4b7
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0011
  - TA0003
techniques:
  - T1219.002
author: Muhammad Faisal
date: '2023-08-03'
falsepositives:
  - Legitimate activity of system administrators
references:
  - https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
  - https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
  - https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_ssm_agent_abuse.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Linux Amazon SSM Agent Hijacking
id: f9b3edc5-3322-4fc7-8aa3-245d646cc4b7
status: test
description: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
references:
    - https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
    - https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
    - https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/
author: Muhammad Faisal
date: 2023-08-03
tags:
    - attack.command-and-control
    - attack.persistence
    - attack.t1219.002
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/amazon-ssm-agent'
        CommandLine|contains|all:
            - '-register '
            - '-code '
            - '-id '
            - '-region '
    condition: selection
falsepositives:
    - Legitimate activity of system administrators
level: medium
```
