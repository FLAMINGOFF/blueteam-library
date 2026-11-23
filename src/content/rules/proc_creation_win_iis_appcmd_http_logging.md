---
title: Disable Windows IIS HTTP Logging
summary: Disables HTTP logging on a Windows IIS web server as seen by Threat Group 3390 (Bronze Union)
sigma_id: e4ed6030-ffe5-4e6a-8a8a-ab3c1ab9d94e
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685.001
author: frack113
date: '2022-01-09'
modified: '2023-01-22'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.002/T1562.002.md#atomic-test-1---disable-windows-iis-http-logging
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_iis_appcmd_http_logging.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Disable Windows IIS HTTP Logging
id: e4ed6030-ffe5-4e6a-8a8a-ab3c1ab9d94e
status: test
description: Disables HTTP logging on a Windows IIS web server as seen by Threat Group 3390 (Bronze Union)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.002/T1562.002.md#atomic-test-1---disable-windows-iis-http-logging
author: frack113
date: 2022-01-09
modified: 2023-01-22
tags:
    - attack.defense-impairment
    - attack.t1685.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\appcmd.exe'
        - OriginalFileName: 'appcmd.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'set'
            - 'config'
            - 'section:httplogging'
            - 'dontLog:true'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
