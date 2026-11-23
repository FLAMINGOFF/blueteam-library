---
title: Enable LM Hash Storage - ProcCreation
summary: |-
  Detects changes to the "NoLMHash" registry value in order to allow Windows to store LM Hashes.
  By setting this registry value to "0" (DWORD), Windows will be allowed to store a LAN manager hash of your password in Active Directory and local SAM databases.
sigma_id: 98dedfdd-8333-49d4-9f23-d7018cccae53
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0112
techniques:
  - T1112
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-12-15'
modified: '2023-12-22'
falsepositives:
  - Unknown
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
  - https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password
  - https://www.sans.org/blog/protecting-privileged-domain-accounts-lm-hashes-the-good-the-bad-and-the-ugly/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_nolmhash.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Enable LM Hash Storage - ProcCreation
id: 98dedfdd-8333-49d4-9f23-d7018cccae53
related:
    - id: c420410f-c2d8-4010-856b-dffe21866437 # Registry
      type: similar
status: test
description: |
    Detects changes to the "NoLMHash" registry value in order to allow Windows to store LM Hashes.
    By setting this registry value to "0" (DWORD), Windows will be allowed to store a LAN manager hash of your password in Active Directory and local SAM databases.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password
    - https://www.sans.org/blog/protecting-privileged-domain-accounts-lm-hashes-the-good-the-bad-and-the-ugly/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-12-15
modified: 2023-12-22
tags:
    - attack.persistence
    - attack.defense-impairment
    - attack.t1112
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - '\System\CurrentControlSet\Control\Lsa'
            - 'NoLMHash'
            - ' 0'
    condition: selection
falsepositives:
    - Unknown
level: high
```
