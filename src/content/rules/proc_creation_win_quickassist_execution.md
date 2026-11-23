---
title: QuickAssist Execution
summary: Detects the execution of Microsoft Quick Assist tool "QuickAssist.exe". This utility can be used by attackers to gain remote access.
sigma_id: e20b5b14-ce93-4230-88af-981983ef6e74
status: experimental
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Muhammad Faisal (@faisalusuf)
date: '2024-12-19'
falsepositives:
  - Legitimate use of Quick Assist in the environment.
references:
  - https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
  - https://www.linkedin.com/posts/kevin-beaumont-security_ive-been-assisting-a-few-orgs-hit-with-successful-activity-7268055739116445701-xxjZ/
  - https://x.com/cyb3rops/status/1862406110365245506
  - https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_quickassist_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: QuickAssist Execution
id: e20b5b14-ce93-4230-88af-981983ef6e74
status: experimental
description: |
    Detects the execution of Microsoft Quick Assist tool "QuickAssist.exe". This utility can be used by attackers to gain remote access.
references:
    - https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
    - https://www.linkedin.com/posts/kevin-beaumont-security_ive-been-assisting-a-few-orgs-hit-with-successful-activity-7268055739116445701-xxjZ/
    - https://x.com/cyb3rops/status/1862406110365245506
    - https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist
author: Muhammad Faisal (@faisalusuf)
date: 2024-12-19
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\QuickAssist.exe'
    condition: selection
falsepositives:
    - Legitimate use of Quick Assist in the environment.
level: low
```
