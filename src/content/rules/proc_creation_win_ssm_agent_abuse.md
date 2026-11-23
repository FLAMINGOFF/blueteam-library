---
title: Potential Amazon SSM Agent Hijacking
summary: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
sigma_id: d20ee2f4-822c-4827-9e15-41500b1fff10
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
  - TA0003
techniques:
  - T1219.002
author: Muhammad Faisal
date: '2023-08-02'
falsepositives:
  - Legitimate activity of system administrators
references:
  - https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
  - https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
  - https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ssm_agent_abuse.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Amazon SSM Agent Hijacking
id: d20ee2f4-822c-4827-9e15-41500b1fff10
status: test
description: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
references:
    - https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
    - https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
    - https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/
author: Muhammad Faisal
date: 2023-08-02
tags:
    - attack.command-and-control
    - attack.persistence
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\amazon-ssm-agent.exe'
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
