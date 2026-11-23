---
title: Use of Scriptrunner.exe
summary: The "ScriptRunner.exe" binary can be abused to proxy execution through it and bypass possible whitelisting
sigma_id: 64760eef-87f7-4ed3-93fd-655668ea9420
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-01'
falsepositives:
  - Legitimate use when App-v is deployed
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Scriptrunner/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_scriptrunner.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of Scriptrunner.exe
id: 64760eef-87f7-4ed3-93fd-655668ea9420
status: test
description: The "ScriptRunner.exe" binary can be abused to proxy execution through it and bypass possible whitelisting
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Scriptrunner/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-01
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\ScriptRunner.exe'
        - OriginalFileName: 'ScriptRunner.exe'
    selection_cli:
        CommandLine|contains: ' -appvscript '
    condition: all of selection*
falsepositives:
    - Legitimate use when App-v is deployed
level: medium
```
