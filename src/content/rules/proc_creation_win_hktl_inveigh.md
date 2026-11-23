---
title: HackTool - Inveigh Execution
summary: Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool
sigma_id: b99a1518-1ad5-4f65-bc95-1ffff97a8fd0
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-24'
modified: '2026-10-31'
falsepositives:
  - Very unlikely
references:
  - https://github.com/Kevin-Robertson/Inveigh
  - https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_inveigh.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Inveigh Execution
id: b99a1518-1ad5-4f65-bc95-1ffff97a8fd0
status: test
description: Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool
references:
    - https://github.com/Kevin-Robertson/Inveigh
    - https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-24
modified: 2026-10-31
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\Inveigh.exe'
        - OriginalFileName:
              - 'Inveigh.exe'
              - 'Inveigh.dll'
        - Description: 'Inveigh'
        - CommandLine|contains:
              - ' -SpooferIP'
              - ' -ReplyToIPs '
              - ' -ReplyToDomains '
              - ' -ReplyToMACs '
              - ' -SnifferIP'
    condition: selection
falsepositives:
    - Very unlikely
level: critical
```
