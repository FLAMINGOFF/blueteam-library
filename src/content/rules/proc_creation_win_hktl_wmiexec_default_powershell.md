---
title: HackTool - Wmiexec Default Powershell Command
summary: Detects the execution of PowerShell with a specific flag sequence that is used by the Wmiexec script
sigma_id: 022eaba8-f0bf-4dd9-9217-4604b0bb3bb0
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-03-08'
falsepositives:
  - Unlikely
references:
  - https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/examples/wmiexec.py
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_wmiexec_default_powershell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Wmiexec Default Powershell Command
id: 022eaba8-f0bf-4dd9-9217-4604b0bb3bb0
status: test
description: Detects the execution of PowerShell with a specific flag sequence that is used by the Wmiexec script
references:
    - https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/examples/wmiexec.py
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-08
tags:
    - attack.lateral-movement
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
