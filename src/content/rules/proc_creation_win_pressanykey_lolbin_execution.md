---
title: Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution
summary: Detects child processes of Microsoft.NodejsTools.PressAnyKey.exe that can be used to execute any other binary
sigma_id: a20391f8-76fb-437b-abc0-dba2df1952c6
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1218
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2022-01-11'
modified: '2023-04-11'
falsepositives:
  - Legitimate use by developers as part of NodeJS development with Visual Studio Tools
references:
  - https://twitter.com/mrd0x/status/1463526834918854661
  - https://gist.github.com/nasbench/a989ce64cefa8081bd50cf6ad8c491b5
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pressanykey_lolbin_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution
id: a20391f8-76fb-437b-abc0-dba2df1952c6
related:
    - id: 65c3ca2c-525f-4ced-968e-246a713d164f
      type: similar
status: test
description: Detects child processes of Microsoft.NodejsTools.PressAnyKey.exe that can be used to execute any other binary
references:
    - https://twitter.com/mrd0x/status/1463526834918854661
    - https://gist.github.com/nasbench/a989ce64cefa8081bd50cf6ad8c491b5
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-01-11
modified: 2023-04-11
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\Microsoft.NodejsTools.PressAnyKey.exe'
    condition: selection
falsepositives:
    - Legitimate use by developers as part of NodeJS development with Visual Studio Tools
level: medium
```
