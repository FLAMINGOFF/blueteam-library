---
title: Renamed NetSupport RAT Execution
summary: Detects the execution of a renamed "client32.exe" (NetSupport RAT) via Imphash, Product and OriginalFileName strings
sigma_id: 0afbd410-de03-4078-8491-f132303cb67d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-19'
modified: '2024-11-23'
falsepositives:
  - Unknown
references:
  - https://redcanary.com/blog/misbehaving-rats/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_netsupport_rat.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed NetSupport RAT Execution
id: 0afbd410-de03-4078-8491-f132303cb67d
status: test
description: Detects the execution of a renamed "client32.exe" (NetSupport RAT) via Imphash, Product and OriginalFileName strings
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-19
modified: 2024-11-23
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Product|contains: 'NetSupport Remote Control'
        - OriginalFileName|contains: 'client32.exe'
        - Hashes|contains: IMPHASH=A9D50692E95B79723F3E76FCF70D023E
    filter:
        Image|endswith: '\client32.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
