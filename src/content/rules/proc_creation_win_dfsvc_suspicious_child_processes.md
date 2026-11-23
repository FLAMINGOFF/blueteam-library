---
title: Potentially Suspicious Child Process Of ClickOnce Application
summary: Detects potentially suspicious child processes of a ClickOnce deployment application
sigma_id: 67bc0e75-c0a9-4cfc-8754-84a505b63c04
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-06-12'
falsepositives:
  - Unknown
references:
  - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_dfsvc_suspicious_child_processes.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Child Process Of ClickOnce Application
id: 67bc0e75-c0a9-4cfc-8754-84a505b63c04
status: test
description: Detects potentially suspicious child processes of a ClickOnce deployment application
references:
    - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-12
tags:
    - attack.execution
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|contains: '\AppData\Local\Apps\2.0\'
        Image|endswith:
            # Add more suspicious processes
            - '\calc.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\explorer.exe'
            - '\mshta.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\nltest.exe'
            - '\notepad.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\reg.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\werfault.exe'
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
