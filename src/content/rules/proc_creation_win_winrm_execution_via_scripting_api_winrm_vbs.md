---
title: Remote Code Execute via Winrm.vbs
summary: Detects an attempt to execute code or create service on remote host via winrm.vbs.
sigma_id: 9df0dd3a-1a5c-47e3-a2bc-30ed177646a0
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1216
author: Julia Fomina, oscd.community
date: '2020-10-07'
modified: '2023-03-03'
falsepositives:
  - Unknown
references:
  - https://twitter.com/bohops/status/994405551751815170
  - https://redcanary.com/blog/lateral-movement-winrm-wmi/
  - https://lolbas-project.github.io/lolbas/Scripts/Winrm/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winrm_execution_via_scripting_api_winrm_vbs.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Code Execute via Winrm.vbs
id: 9df0dd3a-1a5c-47e3-a2bc-30ed177646a0
status: test
description: Detects an attempt to execute code or create service on remote host via winrm.vbs.
references:
    - https://twitter.com/bohops/status/994405551751815170
    - https://redcanary.com/blog/lateral-movement-winrm-wmi/
    - https://lolbas-project.github.io/lolbas/Scripts/Winrm/
author: Julia Fomina, oscd.community
date: 2020-10-07
modified: 2023-03-03
tags:
    - attack.stealth
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        # Note: winrm.vbs can only be run by a process named cscript (see "IsCScriptEnv" function)
        - Image|endswith: '\cscript.exe'
        - OriginalFileName: 'cscript.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'winrm'
            - 'invoke Create wmicimv2/Win32_'
            - '-r:http'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
