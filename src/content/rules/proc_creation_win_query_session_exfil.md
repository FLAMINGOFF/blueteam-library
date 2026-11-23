---
title: Query Usage To Exfil Data
summary: Detects usage of "query.exe" a system binary to exfil information such as "sessions" and "processes" for later use
sigma_id: 53ef0cef-fa24-4f25-a34a-6c72dfa2e6e2
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-01'
modified: '2023-01-19'
falsepositives:
  - Unknown
references:
  - https://twitter.com/MichalKoczwara/status/1553634816016498688
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_query_session_exfil.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Query Usage To Exfil Data
id: 53ef0cef-fa24-4f25-a34a-6c72dfa2e6e2
status: test
description: Detects usage of "query.exe" a system binary to exfil information such as "sessions" and "processes" for later use
references:
    - https://twitter.com/MichalKoczwara/status/1553634816016498688
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-01
modified: 2023-01-19
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: ':\Windows\System32\query.exe'
        CommandLine|contains:
            - 'session >'
            - 'process >'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
