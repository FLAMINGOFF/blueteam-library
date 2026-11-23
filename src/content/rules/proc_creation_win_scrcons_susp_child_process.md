---
title: Script Event Consumer Spawning Process
summary: Detects a suspicious child process of Script Event Consumer (scrcons.exe).
sigma_id: f6d1dd2f-b8ce-40ca-bc23-062efb686b34
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1047
author: Sittikorn S
date: '2021-06-21'
modified: '2022-07-14'
falsepositives:
  - Unknown
references:
  - https://redcanary.com/blog/child-processes/
  - https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/scrcons-exe-rare-child-process.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_scrcons_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Script Event Consumer Spawning Process
id: f6d1dd2f-b8ce-40ca-bc23-062efb686b34
status: test
description: Detects a suspicious child process of Script Event Consumer (scrcons.exe).
references:
    - https://redcanary.com/blog/child-processes/
    - https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/scrcons-exe-rare-child-process.html
author: Sittikorn S
date: 2021-06-21
modified: 2022-07-14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\scrcons.exe'
        Image|endswith:
            - '\svchost.exe'
            - '\dllhost.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\schtasks.exe'
            - '\regsvr32.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
            - '\msbuild.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
