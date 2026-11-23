---
title: Suspicious Usage Of ShellExec_RunDLL
summary: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
sigma_id: d87bd452-6da1-456e-8155-7dc988157b7d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-01'
modified: '2022-12-30'
falsepositives:
  - Unknown
references:
  - https://redcanary.com/blog/raspberry-robin/
  - https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
  - https://github.com/SigmaHQ/sigma/issues/1009
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_susp_shellexec_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Usage Of ShellExec_RunDLL
id: d87bd452-6da1-456e-8155-7dc988157b7d
related:
    - id: 36c5146c-d127-4f85-8e21-01bf62355d5a
      type: obsolete
    - id: 8823e85d-31d8-473e-b7f4-92da070f0fc6
      type: similar
status: test
description: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
references:
    - https://redcanary.com/blog/raspberry-robin/
    - https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
    - https://github.com/SigmaHQ/sigma/issues/1009
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-01
modified: 2022-12-30
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_openasrundll:
        CommandLine|contains: 'ShellExec_RunDLL'
    selection_suspcli:
        CommandLine|contains:
            # Note: The ordinal number may differ depending on the DLL version
            - '\Desktop\'
            - '\Temp\'
            - '\Users\Public\'
            - 'comspec'
            - 'iex'
            - 'Invoke-'
            - 'msiexec'
            - 'odbcconf'
            - 'regsvr32'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
