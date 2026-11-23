---
title: Execute Pcwrun.EXE To Leverage Follina
summary: Detects indirect command execution via Program Compatibility Assistant "pcwrun.exe" leveraging the follina (CVE-2022-30190) vulnerability
sigma_id: 6004abd0-afa4-4557-ba90-49d172e0a299
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0002
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-13'
falsepositives:
  - Unlikely
references:
  - https://twitter.com/nas_bench/status/1535663791362519040
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_pcwrun_follina.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Execute Pcwrun.EXE To Leverage Follina
id: 6004abd0-afa4-4557-ba90-49d172e0a299
status: test
description: Detects indirect command execution via Program Compatibility Assistant "pcwrun.exe" leveraging the follina (CVE-2022-30190) vulnerability
references:
    - https://twitter.com/nas_bench/status/1535663791362519040
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-13
tags:
    - attack.stealth
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\pcwrun.exe'
        CommandLine|contains: '../'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
