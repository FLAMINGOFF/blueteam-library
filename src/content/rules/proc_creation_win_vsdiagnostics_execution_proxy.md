---
title: Potential Binary Proxy Execution Via VSDiagnostics.EXE
summary: Detects execution of "VSDiagnostics.exe" with the "start" command in order to launch and proxy arbitrary binaries.
sigma_id: ac1c92b4-ac81-405a-9978-4604d78cc47e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-08-03'
falsepositives:
  - Legitimate usage for tracing and diagnostics purposes
references:
  - https://twitter.com/0xBoku/status/1679200664013135872
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vsdiagnostics_execution_proxy.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Binary Proxy Execution Via VSDiagnostics.EXE
id: ac1c92b4-ac81-405a-9978-4604d78cc47e
status: test
description: Detects execution of "VSDiagnostics.exe" with the "start" command in order to launch and proxy arbitrary binaries.
references:
    - https://twitter.com/0xBoku/status/1679200664013135872
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-03
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\VSDiagnostics.exe'
        - OriginalFileName: 'VSDiagnostics.exe'
    selection_cli_start:
        CommandLine|contains: 'start'
    selection_cli_launch:
        CommandLine|contains:
            - ' /launch:'
            - ' -launch:'
    condition: all of selection_*
falsepositives:
    - Legitimate usage for tracing and diagnostics purposes
level: medium
```
