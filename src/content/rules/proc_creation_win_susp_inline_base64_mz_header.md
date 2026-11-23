---
title: Base64 MZ Header In CommandLine
summary: Detects encoded base64 MZ header in the commandline
sigma_id: 22e58743-4ac8-4a9f-bf19-00a0428d8c5f
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-12'
falsepositives:
  - Unlikely
references:
  - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_inline_base64_mz_header.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Base64 MZ Header In CommandLine
id: 22e58743-4ac8-4a9f-bf19-00a0428d8c5f
status: test
description: Detects encoded base64 MZ header in the commandline
references:
    - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-12
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'TVqQAAMAAAAEAAAA' # MZ..........
            - 'TVpQAAIAAAAEAA8A'
            - 'TVqAAAEAAAAEABAA'
            - 'TVoAAAAAAAAAAAAA'
            - 'TVpTAQEAAAAEAAAA'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
